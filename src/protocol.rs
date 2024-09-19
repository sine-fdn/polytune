//! Secure multi-party computation protocol with communication via channels.
use std::ops::BitXor;

use garble_lang::circuit::{Circuit, CircuitError, Wire};
use rand::random;
use serde::{Deserialize, Serialize};
use smallvec::smallvec;
use tokio::{runtime::Runtime, task::JoinSet};

use crate::{
    channel::{self, recv_from, recv_vec_from, send_to, Channel, SimpleChannel},
    faand::{self, beaver_aand, bucket_size, fashare, shared_rng, RHO},
    fpre::{fpre, Auth, Delta, Key, Mac, Share},
    garble::{self, decrypt, encrypt, GarblingKey},
    ot::{kos_ot_receiver, kos_ot_sender, u128_to_block},
};

/// Preprocessed AND gates that need to be sent to the circuit evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GarbledGate(pub(crate) [Vec<u8>; 4]);

/// A label for a particular wire in the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Label(pub(crate) u128);

impl BitXor for Label {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<Delta> for Label {
    type Output = Self;

    fn bitxor(self, rhs: Delta) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<Mac> for Label {
    type Output = Self;

    fn bitxor(self, rhs: Mac) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

impl BitXor<Key> for Label {
    type Output = Self;

    fn bitxor(self, rhs: Key) -> Self::Output {
        Label(self.0 ^ rhs.0)
    }
}

fn xor_labels(a: &[Label], b: &[Label]) -> Vec<Label> {
    let mut xor = vec![];
    for (a, b) in a.iter().zip(b) {
        xor.push(*a ^ *b);
    }
    xor
}

/// A custom error type for MPC computation and communication.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelError(channel::Error),
    /// The specified circuit is invalid (e.g. cyclic / contains invalid wirings).
    CircuitError(CircuitError),
    /// A table row could not be encrypted or decrypted.
    GarblingError(garble::Error),
    /// Caused by the preprocessing protocol without trusted dealer.
    PreprocessingError(faand::Error),
    /// Caused by the core MPC protocol computation.
    MpcError(MpcError),
    /// The specified party does not exist in the circuit.
    PartyDoesNotExist,
    /// The number of provided input bits does not match the inputs expected in the circuit.
    WrongInputSize {
        /// The number of input bits specified in the circuit.
        expected: usize,
        /// The number of input bits provided by the user.
        actual: usize,
    },
    /// The output parties list is empty.
    MissingOutputParties,
    /// The output parties list contains an invalid index.
    InvalidOutputParty(usize),
    /// A message was sent, but it contained no data.
    EmptyMsg,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ChannelError(e) => write!(f, "Channel error: {e:?}"),
            Error::CircuitError(e) => write!(f, "Circuit error: {e:?}"),
            Error::GarblingError(e) => write!(f, "Garbling error: {e:?}"),
            Error::PreprocessingError(e) => write!(f, "Preprocessing error: {e:?}"),
            Error::MpcError(e) => write!(f, "MPC error: {e:?}"),
            Error::PartyDoesNotExist => write!(f, "The specified party does not exist"),
            Error::WrongInputSize { expected, actual } => {
                write!(f, "Wrong input, expected {expected} bits, found {actual}")
            }
            Error::MissingOutputParties => write!(f, "Output parties are missing"),
            Error::InvalidOutputParty(p) => write!(f, "Party {p} is not a valid output party"),
            Error::EmptyMsg => f.write_str("The message sent by the other party was empty"),
        }
    }
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
    }
}

impl From<CircuitError> for Error {
    fn from(e: CircuitError) -> Self {
        Self::CircuitError(e)
    }
}

impl From<garble::Error> for Error {
    fn from(e: garble::Error) -> Self {
        Self::GarblingError(e)
    }
}

impl From<faand::Error> for Error {
    fn from(e: faand::Error) -> Self {
        Self::PreprocessingError(e)
    }
}

/// A custom error type for all MPC operations.
#[derive(Debug)]
pub enum MpcError {
    /// No secret share was sent during preprocessing for the specified wire.
    MissingPreprocessingShareForWire(usize),
    /// No secret share was sent in the garbled table for the specified wire.
    MissingTableShareForWire(usize),
    /// No secret share was sent for the specified output wire.
    MissingOutputShareForWire(usize),
    /// No AND share was sent for the specified wire.
    MissingAndShareForWire(usize),
    /// No share was sent for the input wire, possibly because there are fewer parties than inputs.
    MissingSharesForInput(usize),
    /// The input on the specified wire did not match the message authenatication code.
    InvalidInputMacOnWire(usize),
    /// Two different parties tried to provide an input mask for the wire.
    ConflictingInputMask(usize),
    /// The specified wire is not an input wire or the input is missing.
    WireWithoutInput(usize),
    /// No (masked) value was sent for the wire.
    WireWithoutValue(usize),
    /// No label was sent for the wire.
    WireWithoutLabel(usize),
    /// No garbled gate was sent for the specified wire.
    MissingGarbledGate(usize),
    /// The output on the specified wire did not match the message authenatication code.
    InvalidOutputMacOnWire(usize),
    /// The output party received a wrong label from the evaluator.
    InvalidOutputWireLabel(usize),
}

impl From<MpcError> for Error {
    fn from(e: MpcError) -> Self {
        Self::MpcError(e)
    }
}

/// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
pub fn simulate_mpc(
    circuit: &Circuit,
    inputs: &[&[bool]],
    output_parties: &[usize],
    trusted: bool,
) -> Result<Vec<bool>, Error> {
    let tokio = Runtime::new().expect("Could not start tokio runtime");
    tokio.block_on(simulate_mpc_async(circuit, inputs, output_parties, trusted))
}

/// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
pub async fn simulate_mpc_async(
    circuit: &Circuit,
    inputs: &[&[bool]],
    output_parties: &[usize],
    trusted: bool,
) -> Result<Vec<bool>, Error> {
    let p_eval = 0;
    let p_pre = inputs.len();

    let mut channels: Vec<SimpleChannel>;
    if trusted {
        channels = SimpleChannel::channels(inputs.len() + 1);
        let mut channel = channels.pop().unwrap();
        let parties = inputs.len();
        tokio::spawn(async move { fpre(&mut channel, parties).await });
    } else {
        channels = SimpleChannel::channels(inputs.len());
    }

    let mut parties = channels.into_iter().zip(inputs).enumerate();
    let Some(evaluator) = parties.next() else {
        return Ok(vec![]);
    };
    let p_fpre = if trusted {
        Preprocessor::TrustedDealer(p_pre)
    } else {
        Preprocessor::Untrusted
    };

    let mut computation: JoinSet<Vec<bool>> = JoinSet::new();
    for (p_own, (mut channel, inputs)) in parties {
        let circuit = circuit.clone();
        let inputs = inputs.to_vec();
        let output_parties = output_parties.to_vec();
        computation.spawn(async move {
            let result = mpc(
                &mut channel,
                &circuit,
                &inputs,
                p_fpre,
                p_eval,
                p_own,
                &output_parties,
            )
            .await;
            let mut res_party = Vec::new();
            match result {
                Err(e) => {
                    eprintln!("SMPC protocol failed for party {:?}: {:?}", p_own, e);
                }
                Ok(res) => {
                    let mb = channel.bytes_sent as f64 / 1024.0 / 1024.0;
                    println!("Party {p_own} sent {mb:.2}MB of messages");
                    res_party = res;
                }
            }
            res_party
        });
    }
    let (_, (mut party_channel, inputs)) = evaluator;
    let eval_result = mpc(
        &mut party_channel,
        circuit,
        inputs,
        p_fpre,
        p_eval,
        p_eval,
        output_parties,
    )
    .await;
    match eval_result {
        Err(e) => {
            eprintln!("SMPC protocol failed for Evaluator: {:?}", e);
            Ok(vec![])
        }
        Ok(res) => {
            let mut outputs = vec![res];
            while let Some(output) = computation.join_next().await {
                if let Ok(output) = output {
                    outputs.push(output);
                }
            }
            outputs.retain(|o| !o.is_empty());
            if !outputs.windows(2).all(|w| w[0] == w[1]) {
                eprintln!("The result does not match for all output parties: {outputs:?}");
            }
            let mb = party_channel.bytes_sent as f64 / 1024.0 / 1024.0;
            println!("Party {p_eval} sent {mb:.2}MB of messages");
            println!("MPC simulation finished successfully!");
            Ok(outputs.pop().unwrap_or_default())
        }
    }
}

/// Specifies how correlated randomness is provided in the prepocessing phase.
#[derive(Debug, Clone, Copy)]
pub enum Preprocessor {
    /// Correlated randomness is provided by the (semi-)trusted party with the given index.
    TrustedDealer(usize),
    /// The preprocessing is done using OT extension among the parties, no third party necessary.
    Untrusted,
}

/// Executes the MPC protocol for one party and returns the outputs (empty for the contributor).
#[allow(clippy::too_many_arguments)]
pub async fn mpc(
    channel: &mut impl Channel,
    circuit: &Circuit,
    inputs: &[bool],
    p_fpre: Preprocessor,
    p_eval: usize,
    p_own: usize,
    p_out: &[usize],
) -> Result<Vec<bool>, Error> {
    let p_max = circuit.input_gates.len();
    let is_contrib = p_own != p_eval;

    circuit.validate()?;
    let Some(expected_inputs) = circuit.input_gates.get(p_own) else {
        return Err(Error::PartyDoesNotExist);
    };
    if *expected_inputs != inputs.len() {
        return Err(Error::WrongInputSize {
            expected: *expected_inputs,
            actual: inputs.len(),
        });
    }
    if p_out.is_empty() {
        return Err(Error::MissingOutputParties);
    }
    for output_party in p_out {
        if *output_party >= p_max {
            return Err(Error::InvalidOutputParty(*output_party));
        }
    }

    // fn-independent preprocessing:

    let num_input_gates: usize = circuit.input_gates.iter().sum();
    let num_and_gates = circuit.and_gates();
    let num_gates = num_input_gates + circuit.gates.len();
    let secret_bits = num_input_gates + num_and_gates;
    let secret_bits_ot = secret_bits + 3 * RHO;

    let b = bucket_size(num_and_gates);
    let lprime = num_and_gates * b;
    let faand_len = lprime + 3 * RHO;

    let mut sender_ot = vec![vec![0; secret_bits_ot + 3 * faand_len]; p_max];
    let mut receiver_ot = vec![vec![0; secret_bits_ot + 3 * faand_len]; p_max];

    let delta: Delta;
    let mut shared_rand = shared_rng(channel, p_own, p_max).await?;
    let mut x: Vec<bool> = (0..secret_bits_ot + 3 * faand_len)
        .map(|_| random())
        .collect();
    if let Preprocessor::TrustedDealer(p_fpre) = p_fpre {
        send_to::<()>(channel, p_fpre, "delta", &[]).await?;
        delta = recv_from(channel, p_fpre, "delta")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;
    } else {
        delta = Delta(random());
        let deltas = vec![u128_to_block(delta.0); secret_bits_ot + 3 * faand_len];
        for p in (0..p_max).filter(|p| *p != p_own) {
            let sender_out: Vec<(u128, u128)>;
            let recver_out: Vec<u128>;
            if p_own < p {
                sender_out = kos_ot_sender(channel, &mut shared_rand, deltas.clone(), p).await?;
                recver_out = kos_ot_receiver(channel, &mut shared_rand, x.clone(), p).await?;
            } else {
                recver_out = kos_ot_receiver(channel, &mut shared_rand, x.clone(), p).await?;
                sender_out = kos_ot_sender(channel, &mut shared_rand, deltas.clone(), p).await?;
            }

            let sender = sender_out.iter().map(|(first, _)| *first).collect();
            sender_ot[p] = sender;
            receiver_ot[p] = recver_out;
        }
    }

    let random_shares: Vec<Share>;
    let rand_shares: Vec<Share>;
    let auth_bits: Vec<Share>;
    let mut shares = vec![Share(false, Auth(smallvec![])); num_gates];
    let mut labels = vec![Label(0); num_gates];
    let mut xyz_shares = vec![];

    if let Preprocessor::TrustedDealer(p_fpre) = p_fpre {
        send_to(channel, p_fpre, "random shares", &[secret_bits as u32]).await?;
        random_shares = recv_from(channel, p_fpre, "random shares").await?;
    } else {
        rand_shares = fashare(
            (channel, delta),
            &mut x,
            p_own,
            p_max,
            secret_bits + 3 * lprime,
            &mut shared_rand,
            (sender_ot, receiver_ot),
        )
        .await?;

        let (random_shares_vec, xyzbits_vec) = rand_shares.split_at(secret_bits);
        random_shares = random_shares_vec.to_vec();
        xyz_shares = xyzbits_vec.to_vec();
    }

    let mut random_shares = random_shares.into_iter();

    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(_) | Wire::And(_, _) = gate {
            let Some(share) = random_shares.next() else {
                return Err(MpcError::MissingPreprocessingShareForWire(w).into());
            };
            shares[w] = share;
            if is_contrib {
                labels[w] = Label(random());
            }
        }
    }

    // fn-dependent preprocessing:

    let mut and_shares = Vec::new();
    for (w, gate) in circuit.wires().iter().enumerate() {
        match gate {
            Wire::Input(_) => {}
            Wire::Not(x) => {
                shares[w] = shares[*x].clone();
                labels[w] = labels[*x] ^ delta;
            }
            Wire::Xor(x, y) => {
                shares[w] = &shares[*x] ^ &shares[*y];
                labels[w] = labels[*x] ^ labels[*y];
            }
            Wire::And(x, y) => {
                and_shares.push((shares[*x].clone(), shares[*y].clone()));
            }
        }
    }

    if let Preprocessor::TrustedDealer(p_fpre) = p_fpre {
        send_to(channel, p_fpre, "AND shares", &and_shares).await?;
        auth_bits = recv_from(channel, p_fpre, "AND shares").await?;
    } else {
        auth_bits = beaver_aand(
            (channel, delta),
            and_shares.clone(),
            p_own,
            p_max,
            num_and_gates,
            &mut shared_rand,
            xyz_shares,
        )
        .await?;
    }

    let mut auth_bits = auth_bits.into_iter();
    let mut table_shares = vec![None; num_gates];
    let mut garbled_gates = vec![vec![None; num_gates]; p_max];
    if is_contrib {
        let mut preprocessed_gates = vec![None; num_gates];
        for (w, gate) in circuit.wires().iter().enumerate() {
            if let Wire::And(x, y) = gate {
                let Share(r_x, mac_r_x_key_s_x) = shares[*x].clone();
                let Share(r_y, mac_r_y_key_s_y) = shares[*y].clone();
                let Share(r_gamma, mac_r_gamma_key_s_gamma) = shares[w].clone();
                let Some(sigma) = auth_bits.next() else {
                    return Err(MpcError::MissingAndShareForWire(w).into());
                };
                let Share(r_sig, mac_r_sig_key_s_sig) = sigma;
                let r = r_sig ^ r_gamma;
                let mac_r_key_s_0 = &mac_r_sig_key_s_sig ^ &mac_r_gamma_key_s_gamma;
                let mac_r_key_s_1 = &mac_r_key_s_0 ^ &mac_r_x_key_s_x;
                let row0 = Share(r, mac_r_key_s_0.clone());
                let row1 = Share(r ^ r_x, mac_r_key_s_1.clone());
                let row2 = Share(r ^ r_y, &mac_r_key_s_0 ^ &mac_r_y_key_s_y);
                let row3 = Share(
                    r ^ r_x ^ r_y,
                    (&mac_r_key_s_1 ^ &mac_r_y_key_s_y).xor_key(p_eval, delta),
                );

                let label_x_0 = labels[*x];
                let label_y_0 = labels[*y];
                let label_x_1 = label_x_0 ^ delta;
                let label_y_1 = label_y_0 ^ delta;

                let k0 = GarblingKey::new(label_x_0, label_y_0, w, 0);
                let k1 = GarblingKey::new(label_x_0, label_y_1, w, 1);
                let k2 = GarblingKey::new(label_x_1, label_y_0, w, 2);
                let k3 = GarblingKey::new(label_x_1, label_y_1, w, 3);

                let label_gamma_0 = labels[w];
                let row0_label = label_gamma_0 ^ row0.xor_keys() ^ (row0.bit() & delta);
                let row1_label = label_gamma_0 ^ row1.xor_keys() ^ (row1.bit() & delta);
                let row2_label = label_gamma_0 ^ row2.xor_keys() ^ (row2.bit() & delta);
                let row3_label = label_gamma_0 ^ row3.xor_keys() ^ (row3.bit() & delta);

                let garbled0 = encrypt(&k0, (row0.bit(), row0.macs(), row0_label))?;
                let garbled1 = encrypt(&k1, (row1.bit(), row1.macs(), row1_label))?;
                let garbled2 = encrypt(&k2, (row2.bit(), row2.macs(), row2_label))?;
                let garbled3 = encrypt(&k3, (row3.bit(), row3.macs(), row3_label))?;

                preprocessed_gates[w] = Some(GarbledGate([garbled0, garbled1, garbled2, garbled3]));
            }
        }

        send_to(channel, p_eval, "preprocessed gates", &preprocessed_gates).await?;
    } else {
        for p in (0..p_max).filter(|p| *p != p_eval) {
            garbled_gates[p] = recv_vec_from(channel, p, "preprocessed gates", num_gates).await?
        }
        for (w, gate) in circuit.wires().iter().enumerate() {
            if let Wire::And(x, y) = gate {
                let x = shares[*x].clone();
                let y = shares[*y].clone();
                let gamma = shares[w].clone();
                let Share(s_x, mac_s_x_key_r_x) = x;
                let Share(s_y, mac_s_y_key_r_y) = y;
                let Share(s_gamma, mac_s_gamma_key_r_gamma) = gamma;
                let Some(sigma) = auth_bits.next() else {
                    return Err(MpcError::MissingAndShareForWire(w).into());
                };
                let Share(s_sig, mac_s_sig_key_r_sig) = sigma;
                let s = s_sig ^ s_gamma;
                let mac_s_key_r_0 = &mac_s_sig_key_r_sig ^ &mac_s_gamma_key_r_gamma;
                let mac_s_key_r_1 = &mac_s_key_r_0 ^ &mac_s_x_key_r_x;
                let row0 = Share(s, mac_s_key_r_0.clone());
                let row1 = Share(s ^ s_x, mac_s_key_r_1.clone());
                let row2 = Share(s ^ s_y, &mac_s_key_r_0 ^ &mac_s_y_key_r_y);
                let row3 = Share(s ^ s_x ^ s_y ^ true, &mac_s_key_r_1 ^ &mac_s_y_key_r_y);
                table_shares[w] = Some([row0, row1, row2, row3]);
            }
        }
    }

    // input processing:

    let mut wire_shares_for_others =
        vec![vec![None; num_gates]; p_max];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(i) = gate {
            let Share(bit, Auth(macs_and_keys)) = shares[w].clone();
            let Some(mac_and_key) = macs_and_keys.get(*i) else {
                return Err(MpcError::MissingSharesForInput(*i).into());
            };
            if let Some((mac, _)) = mac_and_key {
                wire_shares_for_others[*i][w] = Some((bit, *mac));
            }
        }
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        send_to(channel, p, "wire shares", &wire_shares_for_others[p]).await?;
    }

    let mut wire_shares_from_others =
        vec![vec![None; num_gates]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        wire_shares_from_others[p] = recv_vec_from::<Option<(bool, Mac)>>(channel, p, "wire shares", num_gates).await?;
    }

    let mut inputs = inputs.iter();
    let mut masked_inputs = vec![None; num_gates];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(p_input) = gate {
            if p_own == *p_input {
                let Some(input) = inputs.next() else {
                    return Err(MpcError::WireWithoutInput(w).into());
                };
                let Share(own_share, Auth(own_macs_and_keys)) = shares[w].clone();
                let mut masked_input = *input ^ own_share;
                for p in 0..p_max {
                    if let Some((_, key)) = own_macs_and_keys.get(p).copied().flatten() {
                        let Some(other_shares) = wire_shares_from_others.get(p) else {
                            return Err(MpcError::InvalidInputMacOnWire(w).into());
                        };
                        let Some((other_share, mac)) = other_shares.get(w).copied().flatten()
                        else {
                            return Err(MpcError::InvalidInputMacOnWire(w).into());
                        };
                        if mac != key ^ (other_share & delta) {
                            return Err(MpcError::InvalidInputMacOnWire(w).into());
                        } else {
                            masked_input ^= other_share;
                        }
                    }
                }
                masked_inputs[w] = Some(masked_input)
            }
        }
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        send_to(channel, p, "masked inputs", &masked_inputs).await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        let masked_inputs_from_other_party =
            recv_vec_from::<Option<bool>>(channel, p, "masked inputs", num_gates).await?;
        for (w, mask) in masked_inputs_from_other_party.iter().enumerate() {
            if let Some(mask) = mask {
                if masked_inputs[w].is_some() {
                    return Err(MpcError::ConflictingInputMask(w).into());
                }
                masked_inputs[w] = Some(*mask);
            }
        }
    }

    let mut input_labels = vec![None; num_gates];
    if is_contrib {
        let labels_of_other_inputs: Vec<Option<Label>> = masked_inputs
            .iter()
            .enumerate()
            .map(|(w, input)| input.map(|b| labels[w] ^ (b & delta)))
            .collect();
        send_to(channel, p_eval, "labels", &labels_of_other_inputs).await?;
    } else {
        for p in (0..p_max).filter(|p| *p != p_own) {
            let labels_of_own_inputs =
                recv_vec_from::<Option<Label>>(channel, p, "labels", num_gates).await?;
            for (w, label) in labels_of_own_inputs.iter().enumerate() {
                if let Some(label) = label {
                    let labels = input_labels[w].get_or_insert(vec![Label(0); p_max]);
                    labels[p] = *label;
                }
            }
        }
    }

    // circuit evaluation:

    let mut values: Vec<bool> = vec![];
    let mut labels_eval: Vec<Vec<Label>> = vec![];
    if !is_contrib {
        for (w, gate) in circuit.wires().iter().enumerate() {
            let (input, label) = match gate {
                Wire::Input(_) => {
                    let input = masked_inputs
                        .get(w)
                        .copied()
                        .flatten()
                        .ok_or(MpcError::WireWithoutValue(w))?;
                    let label = input_labels
                        .get(w)
                        .cloned()
                        .flatten()
                        .ok_or(MpcError::WireWithoutLabel(w))?;
                    (input, label.clone())
                }
                Wire::Not(x) => {
                    let input = values[*x];
                    let label = &labels_eval[*x];
                    (!input, label.clone())
                }
                Wire::Xor(x, y) => {
                    let input_x = values[*x];
                    let label_x = &labels_eval[*x];
                    let input_y = values[*y];
                    let label_y = &labels_eval[*y];
                    (input_x ^ input_y, xor_labels(label_x, label_y))
                }
                Wire::And(x, y) => {
                    let input_x = values[*x];
                    let label_x = &labels_eval[*x];
                    let input_y = values[*y];
                    let label_y = &labels_eval[*y];
                    let i = 2 * (input_x as usize) + (input_y as usize);
                    let Some(table_shares) = &table_shares[w] else {
                        return Err(MpcError::MissingTableShareForWire(w).into());
                    };

                    let mut label = vec![Label(0); p_max];
                    let mut macs = vec![vec![]; p_max];
                    let Share(mut s, mac_s_key_r) = table_shares[i].clone();
                    macs[p_eval] = mac_s_key_r.macs();
                    let Auth(mac_s_key_r) = mac_s_key_r;
                    for (p, mac_s_key_r) in mac_s_key_r.iter().enumerate() {
                        let Some((_, key_r)) = mac_s_key_r else {
                            continue;
                        };
                        let Some(GarbledGate(garbled_gate)) = &garbled_gates[p][w] else {
                            return Err(MpcError::MissingGarbledGate(w).into());
                        };
                        let garbling_key = GarblingKey::new(label_x[p], label_y[p], w, i as u8);
                        let garbled_row = garbled_gate[i].clone();
                        let (r, mac_r, label_share) = decrypt(&garbling_key, &garbled_row)?;
                        let Some(mac_r_for_eval) = mac_r.get(p_eval).copied().flatten() else {
                            return Err(MpcError::InvalidInputMacOnWire(w).into());
                        };
                        if mac_r_for_eval != *key_r ^ (r & delta) {
                            return Err(MpcError::InvalidInputMacOnWire(w).into());
                        }
                        s ^= r;
                        label[p] = label_share;
                        macs[p] = mac_r;
                    }
                    for p_i in (0..p_max).filter(|p_i| *p_i != p_eval) {
                        for p_j in (0..p_max).filter(|p_j| *p_j != p_i) {
                            if let Some(macs) = macs.get(p_j) {
                                if let Some(mac) = macs.get(p_i).copied().flatten() {
                                    label[p_i] = label[p_i] ^ mac
                                }
                            }
                        }
                    }
                    (s, label)
                }
            };
            values.push(input);
            labels_eval.push(label);
        }
    }

    // output determination:

    let mut outputs = vec![None; num_gates];
    for p_out in p_out.iter().copied().filter(|p| *p != p_own) {
        for w in circuit.output_gates.iter().copied() {
            let Share(bit, Auth(macs_and_keys)) = shares[w].clone();
            if let Some((mac, _)) = macs_and_keys.get(p_out).copied().flatten() {
                outputs[w] = Some((bit, mac));
            }
        }
        send_to(channel, p_out, "output wire shares", &outputs).await?;
    }
    let mut output_wire_shares: Vec<Vec<Option<(bool, Mac)>>> = vec![vec![]; p_max];
    if p_out.contains(&p_own) {
        for p in (0..p_max).filter(|p| *p != p_own) {
            output_wire_shares[p] =
                recv_vec_from(channel, p, "output wire shares", num_gates).await?;
        }
    }
    let mut input_wires = vec![None; num_gates];
    if !is_contrib {
        for p_out in p_out.iter().copied().filter(|p| *p != p_own) {
            let mut wires_and_labels = vec![None; num_gates];
            for w in circuit.output_gates.iter().copied() {
                wires_and_labels[w] = Some((values[w], labels_eval[w][p_out]));
            }
            send_to(channel, p_out, "lambda", &wires_and_labels).await?;
        }
        for w in circuit.output_gates.iter().copied() {
            input_wires[w] = Some(values[w]);
        }
    } else if p_out.contains(&p_own) {
        let wires_and_labels =
            recv_vec_from::<Option<(bool, Label)>>(channel, p_eval, "lambda", num_gates).await?;
        for w in circuit.output_gates.iter().copied() {
            if !(wires_and_labels[w] == Some((true, labels[w] ^ delta))
                || wires_and_labels[w] == Some((false, labels[w])))
            {
                return Err(MpcError::InvalidOutputWireLabel(w).into());
            }
            input_wires[w] = wires_and_labels[w].map(|(bit, _)| bit);
        }
    }
    let mut outputs = vec![];
    if p_out.contains(&p_own) {
        let mut output_wires = vec![None; num_gates];
        for w in circuit.output_gates.iter().copied() {
            let Some(input) = input_wires.get(w).copied().flatten() else {
                return Err(MpcError::MissingOutputShareForWire(w).into());
            };
            let Share(bit, _) = &shares[w];
            output_wires[w] = Some(input ^ bit);
        }
        for p in (0..p_max).filter(|p| *p != p_own) {
            for (w, output_wire) in output_wire_shares[p].iter().enumerate() {
                let Share(_, Auth(mac_s_key_r)) = &shares[w];
                let Some((_, key_r)) = mac_s_key_r.get(p).copied().flatten() else {
                    return Err(MpcError::InvalidOutputMacOnWire(w).into());
                };
                if let Some((r, mac_r)) = output_wire {
                    if *mac_r != key_r ^ (*r & delta) {
                        return Err(MpcError::InvalidOutputMacOnWire(w).into());
                    } else if let Some(o) = output_wires.get(w).copied().flatten() {
                        output_wires[w] = Some(o ^ r);
                    };
                }
            }
        }
        for w in circuit.output_gates.iter() {
            if let Some(o) = output_wires.get(*w).copied().flatten() {
                outputs.push(o);
            }
        }
    }

    Ok(outputs)
}
