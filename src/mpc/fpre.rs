//! The FPre preprocessor as a (semi-)trusted party, providing correlated randomness.

use futures_util::future::try_join_all;
use rand::random;
use tracing::{Level, debug, instrument};

use crate::{
    channel::{self, Channel, recv_from, send_to},
    mpc::data_types::{Auth, Delta, Key, Mac, Share},
};

/// Errors that can occur while executing FPre as a trusted dealer.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum Error {
    /// One of the parties tried to cheat.
    CheatingDetected,
    /// The parties expect a different number of random shares.
    RandomSharesMismatch(u32, u32),
    /// The parties expect a different number of AND shares.
    AndSharesMismatch(usize, usize),
    /// An error occurred while trying to communicate over the channel.
    Channel(channel::Error),
    /// A message was sent, but it contained no data.
    EmptyMsg,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CheatingDetected => f.write_str("Cheating detected"),
            Error::RandomSharesMismatch(a, b) => write!(f, "Unequal number of shares: {a} vs {b}"),
            Error::AndSharesMismatch(a, b) => write!(f, "Unequal number of AND shares: {a} vs {b}"),
            Error::Channel(e) => write!(f, "Channel error: {e:?}"),
            Error::EmptyMsg => f.write_str("The message sent by the other party was empty"),
        }
    }
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Error::Channel(e)
    }
}

/// Runs FPre as a trusted dealer, communicating with all other parties.
#[allow(dead_code)]
#[instrument(level=Level::DEBUG, skip_all, err)]
pub(crate) async fn fpre(channel: &(impl Channel + Send), parties: usize) -> Result<(), Error> {
    debug!("FPre with {parties} parties");
    try_join_all((0..parties).map(async |p| recv_from::<()>(channel, p, "delta (fpre)").await))
        .await?;

    let deltas = try_join_all((0..parties).map(async |p| {
        let delta = Delta(random());
        send_to(channel, p, "delta (fpre)", &[delta]).await?;
        Ok::<_, Error>(delta)
    }))
    .await?;

    debug!("FPre sent deltas to all parties");

    let num_shares: Vec<u32> = try_join_all((0..parties).map(async |p| {
        recv_from(channel, p, "random shares (fpre)")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)
    }))
    .await?;

    for window in num_shares.windows(2) {
        let &[a, b] = window else {
            unreachable!("window is size 2")
        };
        if a != b {
            let e = Error::RandomSharesMismatch(a, b);
            try_join_all(
                (0..parties).map(async |p| send_to(channel, p, "error", &[format!("{e:?}")]).await),
            )
            .await?;
            return Err(e);
        }
    }

    let num_shares = num_shares.first().copied().unwrap_or_default() as usize;
    let mut random_shares = vec![vec![]; parties];
    for _ in 0..num_shares {
        let mut bits = vec![];
        let mut keys = vec![];
        for i in 0..parties {
            bits.push(random());
            keys.push(vec![Key::default(); parties]);
            for (j, key) in keys[i].iter_mut().enumerate() {
                if i != j {
                    *key = Key(random());
                }
            }
        }
        for i in 0..parties {
            let mut mac_and_key = vec![(Mac::default(), Key::default()); parties];
            for j in 0..parties {
                if i != j {
                    let mac = keys[j][i] ^ (bits[i] & deltas[j]);
                    let key = keys[i][j];
                    mac_and_key[j] = (mac, key);
                }
            }
            random_shares[i].push(Share(bits[i], Auth(mac_and_key)));
        }
    }
    try_join_all(
        random_shares
            .into_iter()
            .enumerate()
            .map(async |(p, shares)| send_to(channel, p, "random shares (fpre)", &shares).await),
    )
    .await?;

    debug!("FPre sent random shares to all parties");

    let all_and_shares: Vec<Vec<(Share, Share)>> =
        try_join_all((0..parties).map(async |p| recv_from(channel, p, "AND shares (fpre)").await))
            .await?;

    let mut num_shares = None;
    let mut shares = vec![];
    for and_shares in all_and_shares {
        if let Some(num_shares) = num_shares {
            if num_shares != and_shares.len() {
                let e = Error::AndSharesMismatch(num_shares, and_shares.len());
                try_join_all(
                    (0..parties)
                        .map(async |p| send_to(channel, p, "error", &[format!("{e:?}")]).await),
                )
                .await?;
                return Err(e);
            }
        } else {
            for _ in 0..and_shares.len() {
                shares.push(vec![]);
            }
        }
        num_shares = Some(and_shares.len());
        for (s, (a, b)) in and_shares.into_iter().enumerate() {
            shares[s].push((a, b))
        }
    }
    let mut has_cheated = false;
    for share in shares.iter() {
        for (i, (a, b)) in share.iter().enumerate() {
            for (Share(bit, Auth(macs_i)), round) in [(a, 0), (b, 1)] {
                for (j, (mac_i, _)) in macs_i.iter().enumerate() {
                    if *mac_i != Mac::default() {
                        // Added when removed Option
                        let (a, b) = &share[j];
                        let Share(_, Auth(keys_j)) = if round == 0 { a } else { b };
                        let (_, key_j) = keys_j[i];
                        if *mac_i != key_j ^ (*bit & deltas[j]) {
                            has_cheated = true;
                        }
                    }
                }
            }
        }
    }
    if has_cheated {
        let e = Error::CheatingDetected;
        try_join_all(
            (0..parties).map(async |p| send_to(channel, p, "error", &[format!("{e:?}")]).await),
        )
        .await?;
        return Err(e);
    }
    let mut and_shares = vec![vec![]; parties];
    for share in shares {
        let mut a = false;
        let mut b = false;
        for (Share(a_i, _), Share(b_i, _)) in share {
            a ^= a_i;
            b ^= b_i;
        }
        let c = a & b;
        let mut current_share = false;
        let mut bits = vec![false; parties];
        let mut keys = vec![];
        for i in 0..parties {
            bits[i] = if i == parties - 1 {
                current_share != c
            } else {
                let share: bool = random();
                current_share ^= share;
                share
            };
            keys.push(vec![Key::default(); parties]);
            for (j, key) in keys[i].iter_mut().enumerate() {
                if i != j {
                    *key = Key(random());
                }
            }
        }
        for i in 0..parties {
            let mut mac_and_key = vec![(Mac::default(), Key::default()); parties];
            for j in 0..parties {
                if i != j {
                    let mac = keys[j][i] ^ (bits[i] & deltas[j]);
                    let key = keys[i][j];
                    mac_and_key[j] = (mac, key);
                }
            }
            and_shares[i].push(Share(bits[i], Auth(mac_and_key)));
        }
    }
    try_join_all(
        and_shares
            .into_iter()
            .enumerate()
            .map(async |(p, and_shares)| {
                send_to(channel, p, "AND shares (fpre)", &and_shares).await
            }),
    )
    .await?;

    debug!("FPre sent AND shares to all parties");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        channel::{SimpleChannel, recv_from, recv_vec_from, send_to},
        mpc::{
            fpre::{Auth, Delta, Error, Key, Mac, Share, fpre},
            protocol::{_mpc, Context, Preprocessor},
        },
    };
    use garble_lang::{
        CircuitKind, CompileOptions, compile_with_options, register_circuit::Circuit,
    };

    #[tokio::test]
    async fn xor_homomorphic_mac() -> Result<(), Error> {
        let parties = 2;
        let mut channels = SimpleChannel::channels(parties + 1);
        let channel = channels.pop().unwrap();
        tokio::spawn(async move { fpre(&channel, parties).await });
        let fpre_party = parties;
        let b = channels.pop().unwrap();
        let a = channels.pop().unwrap();

        // init:
        send_to::<()>(&a, fpre_party, "delta", &[]).await?;
        send_to::<()>(&b, fpre_party, "delta", &[]).await?;
        let delta_a: Delta = recv_from(&a, fpre_party, "delta")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
        let delta_b: Delta = recv_from(&b, fpre_party, "delta")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;

        // random r1, r2, s1, s2:
        send_to(&a, fpre_party, "random shares", &[2_u32]).await?;
        send_to(&b, fpre_party, "random shares", &[2_u32]).await?;

        let mut r = recv_vec_from(&a, fpre_party, "random shares", 2)
            .await?
            .into_iter();
        let mut s = recv_vec_from(&b, fpre_party, "random shares", 2)
            .await?
            .into_iter();

        let (auth_r1, auth_r2) = (r.next().unwrap(), r.next().unwrap());
        let (auth_s1, auth_s2) = (s.next().unwrap(), s.next().unwrap());
        let (Share(r1, Auth(mac_r1_key_s1)), Share(r2, Auth(mac_r2_key_s2))) = (auth_r1, auth_r2);
        let (Share(s1, Auth(mac_s1_key_r1)), Share(s2, Auth(mac_s2_key_r2))) = (auth_s1, auth_s2);
        let (mac_r1, key_s1) = mac_r1_key_s1[1];
        let (mac_r2, key_s2) = mac_r2_key_s2[1];
        let (mac_s1, key_r1) = mac_s1_key_r1[0];
        let (mac_s2, key_r2) = mac_s2_key_r2[0];

        let (r3, mac_r3, key_s3) = {
            let r3 = r1 ^ r2;
            let mac_r3 = mac_r1 ^ mac_r2;
            let key_s3 = key_s1 ^ key_s2;
            (r3, mac_r3, key_s3)
        };
        let (s3, mac_s3, key_r3) = {
            let s3 = s1 ^ s2;
            let mac_s3 = mac_s1 ^ mac_s2;
            let key_r3 = key_r1 ^ key_r2;
            (s3, mac_s3, key_r3)
        };
        // verify that the MAC is XOR-homomorphic:
        assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
        assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_and_shares() -> Result<(), Error> {
        for i in 0..3 {
            let parties = 2;
            let mut channels = SimpleChannel::channels(parties + 1);
            let channel = channels.pop().unwrap();
            tokio::spawn(async move { fpre(&channel, parties).await });
            let fpre_party = parties;
            let b = channels.pop().unwrap();
            let a = channels.pop().unwrap();

            // init:
            send_to::<()>(&a, fpre_party, "delta", &[]).await?;
            send_to::<()>(&b, fpre_party, "delta", &[]).await?;
            let delta_a: Delta = recv_from(&a, fpre_party, "delta")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;
            let delta_b: Delta = recv_from(&b, fpre_party, "delta")
                .await?
                .pop()
                .ok_or(Error::EmptyMsg)?;

            // random r1, r2, s1, s2:
            send_to(&a, fpre_party, "random shares", &[2_u32]).await?;
            send_to(&b, fpre_party, "random shares", &[2_u32]).await?;

            let mut r = recv_vec_from::<Share>(&a, fpre_party, "random shares", 2)
                .await?
                .into_iter();
            let mut s = recv_vec_from::<Share>(&b, fpre_party, "random shares", 2)
                .await?
                .into_iter();

            let (auth_r1, auth_r2) = (r.next().unwrap(), r.next().unwrap());
            let (auth_s1, auth_s2) = (s.next().unwrap(), s.next().unwrap());
            let (Share(r1, Auth(mac_r1_key_s1)), Share(r2, _)) = (auth_r1.clone(), auth_r2.clone());
            let (Share(s1, Auth(mac_s1_key_r1)), Share(s2, _)) = (auth_s1.clone(), auth_s2.clone());
            let (mac_r1, key_s1) = mac_r1_key_s1[1];
            let (_, key_r1) = mac_s1_key_r1[0];

            if i == 0 {
                // uncorrupted authenticated (r1 XOR s1) AND (r2 XOR s2):
                send_to(&a, fpre_party, "AND shares", &[(auth_r1, auth_r2)]).await?;
                send_to(&b, fpre_party, "AND shares", &[(auth_s1, auth_s2)]).await?;
                let Share(r3, Auth(mac_r3_key_s3)) =
                    recv_from::<Share>(&a, fpre_party, "AND shares")
                        .await?
                        .pop()
                        .unwrap();
                let Share(s3, Auth(mac_s3_key_r3)) =
                    recv_from::<Share>(&b, fpre_party, "AND shares")
                        .await?
                        .pop()
                        .unwrap();
                let (mac_r3, key_s3) = mac_r3_key_s3[1];
                let (mac_s3, key_r3) = mac_s3_key_r3[0];
                assert_eq!(r3 ^ s3, (r1 ^ s1) & (r2 ^ s2));
                assert_eq!(mac_r3, key_r3 ^ (r3 & delta_b));
                assert_eq!(mac_s3, key_s3 ^ (s3 & delta_a));
            } else if i == 1 {
                // corrupted (r1 XOR s1) AND (r2 XOR s2):
                let auth_r1_corrupted = Share(
                    !r1,
                    Auth(vec![(Mac::default(), Key::default()), (mac_r1, key_s1)]),
                );
                send_to(
                    &a,
                    fpre_party,
                    "AND shares",
                    &[(auth_r1_corrupted, auth_r2)],
                )
                .await?;
                send_to(&b, fpre_party, "AND shares", &[(auth_s1, auth_s2)]).await?;
                assert_eq!(
                    recv_from::<String>(&a, fpre_party, "AND shares").await?,
                    vec!["CheatingDetected".to_string()]
                );
                assert_eq!(
                    recv_from::<String>(&b, fpre_party, "AND shares").await?,
                    vec!["CheatingDetected".to_string()]
                );
            } else if i == 2 {
                // A would need knowledge of B's key and delta to corrupt the shared secret:
                let mac_r1_corrupted = key_r1 ^ (!r1 & delta_b);
                let auth_r1_corrupted = Share(
                    !r1,
                    Auth(vec![
                        (Mac::default(), Key::default()),
                        (mac_r1_corrupted, key_s1),
                    ]),
                );
                send_to(
                    &a,
                    fpre_party,
                    "AND shares",
                    &[(auth_r1_corrupted, auth_r2)],
                )
                .await?;
                send_to(&b, fpre_party, "AND shares", &[(auth_s1, auth_s2)]).await?;
                assert_eq!(
                    recv_from::<Share>(&a, fpre_party, "AND shares")
                        .await?
                        .len(),
                    1
                );
                assert_eq!(
                    recv_from::<Share>(&b, fpre_party, "AND shares")
                        .await?
                        .len(),
                    1
                );
            }
        }
        Ok(())
    }

    #[test]
    fn eval_garble_prg_3pc_td() -> Result<(), Error> {
        let output_parties: Vec<usize> = vec![0, 1, 2];
        let prg = compile_with_options(
            "pub fn main(x: u8, y: u8, z: u8) -> u8 { x * y * z }",
            CompileOptions {
                circuit_kind: CircuitKind::Register,
                ..Default::default()
            },
        )
        .unwrap();
        for x in 0..3 {
            for y in 0..3 {
                for z in 0..3 {
                    let expected = x * y * z;
                    let calculation = format!("{x}u8 * {y}u8 * {z}u8");
                    let x = prg.parse_arg(0, &format!("{x}u8")).unwrap().as_bits();
                    let y = prg.parse_arg(1, &format!("{y}u8")).unwrap().as_bits();
                    let z = prg.parse_arg(2, &format!("{z}u8")).unwrap().as_bits();
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .expect("Could not start tokio runtime");
                    let output = rt.block_on(simulate_mpc_trusted_dealer(
                        prg.circuit.unwrap_register_ref(),
                        &[&x, &y, &z],
                        &output_parties,
                    ))?;
                    let result = prg.parse_output(&output).unwrap();
                    println!("{calculation} = {result}");
                    assert_eq!(format!("{result}"), format!("{expected}"));
                }
            }
        }
        Ok(())
    }

    /// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
    async fn simulate_mpc_trusted_dealer(
        circuit: &Circuit,
        inputs: &[&[bool]],
        output_parties: &[usize],
    ) -> Result<Vec<bool>, Error> {
        let p_eval = 0;
        let p_pre = inputs.len();

        let mut channels: Vec<SimpleChannel>;
        channels = SimpleChannel::channels(inputs.len() + 1);
        let channel = channels.pop().unwrap();
        let parties = inputs.len();
        tokio::spawn(async move { crate::mpc::fpre::fpre(&channel, parties).await });

        let mut parties = channels.into_iter().zip(inputs).enumerate();
        let Some((_, (eval_channel, inputs))) = parties.next() else {
            return Ok(vec![]);
        };
        let p_fpre = Preprocessor::TrustedDealer(p_pre);

        let mut computation: tokio::task::JoinSet<(Vec<bool>, usize)> = tokio::task::JoinSet::new();

        for (p_own, (channel, inputs)) in parties {
            let circuit = circuit.clone();
            let inputs = inputs.to_vec();
            let output_parties = output_parties.to_vec();
            computation.spawn(async move {
                let ctx = Context::new(
                    &channel,
                    &circuit,
                    &inputs,
                    p_fpre,
                    p_eval,
                    p_own,
                    &output_parties,
                    None,
                );
                match _mpc(&ctx).await {
                    Ok(res) => {
                        println!(
                            "Party {p_own} sent {:.2}MB of messages",
                            channel.bytes_sent() as f64 / 1024.0 / 1024.0
                        );
                        (res, p_own)
                    }
                    Err(e) => {
                        panic!("SMPC protocol failed for party {p_own}: {e:?}");
                    }
                }
            });
        }
        let ctx = Context::new(
            &eval_channel,
            circuit,
            inputs,
            p_fpre,
            p_eval,
            p_eval,
            output_parties,
            None,
        );
        let eval_result = _mpc(&ctx).await;
        let mut outputs = vec![vec![]; circuit.input_regs.len()];
        match eval_result {
            Err(e) => {
                panic!("SMPC protocol failed for Evaluator: {e:?}");
            }
            Ok(res) => {
                outputs[p_eval] = res;
                while let Some(output) = computation.join_next().await {
                    if let Ok((out, p)) = output {
                        outputs[p] = out;
                    }
                }
                let expected_output = outputs[output_parties[0]].clone();
                for &p in &output_parties[1..] {
                    if outputs[p] != expected_output {
                        panic!("The result does not match for all output parties: {outputs:?}");
                    }
                }
                let mb = eval_channel.bytes_sent() as f64 / 1024.0 / 1024.0;
                println!("Party {p_eval} sent {mb:.2}MB of messages");
                println!("MPC simulation finished successfully!");
                Ok(outputs.pop().unwrap_or_default())
            }
        }
    }
}
