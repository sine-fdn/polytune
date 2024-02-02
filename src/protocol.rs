//! Secure 2-party computation protocol with communication via channels.
use std::ops::BitXor;

use garble_lang::circuit::{Circuit, CircuitError, Wire};
use rand::random;
use serde::{Deserialize, Serialize};
use tokio::{runtime::Runtime, task};

use crate::{
    channel::{self, Channel, MsgChannel, SimpleChannel},
    fpre::{f_pre, Auth, Delta, Key, Mac, Share},
    garble::{self, decrypt, encrypt, GarblingKey},
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

/// A custom error type for SMPC computation and communication.
#[derive(Debug)]
pub enum Error {
    /// A message could not be sent or received.
    ChannelError(channel::Error),
    /// The specified circuit is invalid (e.g. cyclic / contains invalid wirings).
    CircuitError(CircuitError),
    /// A table row could not be encrypted or decrypted.
    GarblingError(garble::Error),
    /// Caused by the core SMPC protocol computation.
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

/// A custom error type for all MPC operations.
#[derive(Debug)]
pub enum MpcError {
    /// No secret share was sent for the specified wire.
    MissingShareForWire(usize),
    /// No AND share was sent for the specified wire.
    MissingAndShareForWire(usize),
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
    output_parties: Vec<usize>,
) -> Result<Vec<bool>, Error> {
    let n_parties = inputs.len();
    let p_eval = 0;
    let mut counter: usize = 1; //for PartyContribOutput parties, starting from 1 as we do not want party 0 to be PartyContribOutput, it should be PartyEval
    let tokio = Runtime::new().expect("Could not start tokio runtime");
    let parties = SimpleChannel::channels(n_parties);
    tokio.block_on(async {
        let fpre_channels = f_pre(inputs.len()).await;

        let mut parties = fpre_channels
            .into_iter()
            .zip(parties)
            .zip(inputs)
            .enumerate();
        let Some(evaluator) = parties.next() else {
            return Ok(vec![]);
        };

        let mut output: Vec<bool> = Vec::new();
        let mut computation: Vec<tokio::task::JoinHandle<Vec<bool>>> =
            Vec::with_capacity(n_parties);

        for (p_own, ((fpre_channel, party_channel), inputs)) in parties {
            let circuit = circuit.clone();
            let inputs = inputs.to_vec();
            let output_parties = output_parties.clone();
            computation.push(task::spawn(async move {
                let result: Result<Vec<bool>, Error> = mpc(
                    &circuit,
                    &inputs,
                    fpre_channel,
                    party_channel,
                    p_eval,
                    p_own,
                    if output_parties.contains(&counter) {
                        Role::PartyContribOutput
                    } else {
                        Role::PartyContrib
                    },
                    output_parties,
                )
                .await;
                let mut res_party: Vec<bool> = Vec::new();
                match result {
                    Err(e) => {
                        eprintln!("SMPC protocol failed for party {:?}: {:?}", p_own, e);
                    }
                    Ok(res) => {
                        res_party = res;
                    }
                }
                res_party
            }));
            counter += 1;
        }
        let (_, ((fpre_channel, party_channel), inputs)) = evaluator;
        let eval_result = mpc(
            circuit,
            inputs,
            fpre_channel,
            party_channel,
            p_eval,
            p_eval,
            Role::PartyEval,
            output_parties,
        )
        .await;
        match eval_result {
            Err(e) => {
                eprintln!("SMPC protocol failed for Evaluator: {:?}", e);
            }
            Ok(res) => {
                if !res.is_empty() {
                    output = res;
                }
                for i in computation {
                    let bool_vec_res = i.await.unwrap();
                    if !bool_vec_res.is_empty() {
                        // true for output parties
                        if !output.is_empty() {
                            if output != bool_vec_res {
                                eprintln!(
                                    "{:?} The result does not match for all output parties! {:?}",
                                    bool_vec_res, output
                                );
                            }
                        } else {
                            output = bool_vec_res;
                        }
                    }
                }
            }
        }
        Ok(output)
    })
}

/// The role played by a particular party in the protocol execution.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    /// The party contributes inputs but does not evaluate the circuit.
    PartyContrib,
    /// The party contributes inputs, does not evaluate the circuit but receives output.
    PartyContribOutput,
    /// The party contributes inputs and evaluates the circuit (and therefore receives output).
    PartyEval,
}

/// Executes the MPC protocol for one party and returns the outputs (empty for the contributor).
#[allow(clippy::too_many_arguments)]
pub async fn mpc<Fpre: Channel, Party: Channel>(
    circuit: &Circuit,
    inputs: &[bool],
    mut fpre: MsgChannel<Fpre>,
    mut parties: MsgChannel<Party>,
    p_eval: usize,
    p_own: usize,
    role: Role,
    output_parties: Vec<usize>,
) -> Result<Vec<bool>, Error> {
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

    let fpre_party = 0;
    let p_max = parties.participants();

    // fn-independent preprocessing:

    fpre.send_to(fpre_party, "delta", &()).await?;
    let delta: Delta = fpre.recv_from(fpre_party, "delta").await?;

    let num_input_gates: usize = circuit.input_gates.iter().sum();
    let num_and_gates = circuit.and_gates();
    let num_gates = num_input_gates + circuit.gates.len();
    let secret_bits = num_input_gates + num_and_gates;
    fpre.send_to(fpre_party, "random shares", &(secret_bits as u32))
        .await?;

    let random_shares: Vec<Share> = fpre.recv_from(fpre_party, "random shares").await?;
    let mut random_shares = random_shares.into_iter();

    //let mut wire_shares_and_labels = vec![(Share(false, Auth(vec![])), Label(0)); num_gates];
    let mut shares = vec![Share(false, Auth(vec![])); num_gates];
    let mut labels = vec![Label(0); num_gates];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(_) | Wire::And(_, _) = gate {
            let Some(share) = random_shares.next() else {
                return Err(MpcError::MissingShareForWire(w).into());
            };
            let label = match role {
                Role::PartyContrib => Label(random()),
                Role::PartyContribOutput => Label(random()),
                // the labels are calculated later by the evaluator, so we just use 0 for now:
                Role::PartyEval => Label(0),
            };
            shares[w] = share;
            labels[w] = label;
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
    fpre.send_to(fpre_party, "AND shares", &and_shares).await?;
    let auth_bits: Vec<Share> = fpre.recv_from(fpre_party, "AND shares").await?;
    let mut auth_bits = auth_bits.into_iter();
    let mut table_shares = vec![None; num_gates];
    let mut garbled_gates: Vec<Vec<Option<GarbledGate>>> = vec![vec![None; num_gates]; p_max];
    if let Role::PartyContrib | Role::PartyContribOutput = role {
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
        parties
            .send_to(p_eval, "preprocessed gates", &preprocessed_gates)
            .await?;
    } else {
        for p in (0..p_max).filter(|p| *p != p_eval) {
            garbled_gates[p] = parties.recv_from(p, "preprocessed gates").await?
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

    let mut wire_shares_for_others: Vec<Vec<Option<(bool, Mac)>>> =
        vec![vec![None; num_gates]; p_max];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(i) = gate {
            let Share(bit, Auth(macs_and_keys)) = shares[w].clone();
            if let Some((mac, _)) = macs_and_keys[*i] {
                wire_shares_for_others[*i][w] = Some((bit, mac));
            }
        }
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        parties
            .send_to(p, "wire shares", &wire_shares_for_others[p])
            .await?;
    }

    let mut wire_shares_from_others: Vec<Vec<Option<(bool, Mac)>>> =
        vec![vec![None; num_gates]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        wire_shares_from_others[p] = parties.recv_vec_from(p, "wire shares", num_gates).await?;
    }

    let mut inputs = inputs.iter();
    let mut masked_inputs: Vec<Option<bool>> = vec![None; num_gates];
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
        parties.send_to(p, "masked inputs", &masked_inputs).await?;
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        let masked_inputs_from_other_party: Vec<Option<bool>> =
            parties.recv_vec_from(p, "masked inputs", num_gates).await?;
        for (w, mask) in masked_inputs_from_other_party.iter().enumerate() {
            if let Some(mask) = mask {
                if masked_inputs[w].is_some() {
                    return Err(MpcError::ConflictingInputMask(w).into());
                }
                masked_inputs[w] = Some(*mask);
            }
        }
    }

    let mut input_labels: Vec<Option<Vec<Label>>> = vec![None; num_gates];
    if let Role::PartyContrib | Role::PartyContribOutput = role {
        let labels_of_other_inputs: Vec<Option<Label>> = masked_inputs
            .iter()
            .enumerate()
            .map(|(w, input)| input.map(|b| labels[w] ^ (b & delta)))
            .collect();
        parties
            .send_to(p_eval, "labels", &labels_of_other_inputs)
            .await?;
    } else {
        for p in (0..p_max).filter(|p| *p != p_own) {
            let labels_of_own_inputs: Vec<Option<Label>> =
                parties.recv_vec_from(p, "labels", num_gates).await?;
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
    if let Role::PartyContrib | Role::PartyContribOutput = role {
        // nothing to do for party A
    } else {
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
                        return Err(MpcError::MissingShareForWire(w).into());
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

    let mut outputs: Vec<Option<(bool, Mac)>> = vec![None; num_gates];
    for output_party in &output_parties {
        if *output_party != p_own {
            for w in circuit.output_gates.iter().copied() {
                let Share(bit, Auth(macs_and_keys)) = shares[w].clone();
                if let Some((mac, _)) = macs_and_keys.get(*output_party).copied().flatten() {
                    outputs[w] = Some((bit, mac));
                }
            }
            parties
                .send_to(*output_party, "output wire shares", &outputs)
                .await?; // all parties send to output parties and evaluator (except itself)
        }
    }
    let mut output_wire_shares: Vec<Vec<Option<(bool, Mac)>>> = vec![vec![]; p_max];
    if output_parties.contains(&p_own) {
        for p in (0..p_max).filter(|p| *p != p_own) {
            output_wire_shares[p] = parties
                .recv_vec_from(p, "output wire shares", num_gates)
                .await?; // output parties receive shares from all parties
        }
    }
    let mut wires_and_labels: Vec<Option<(bool, Label)>> = vec![None; num_gates];
    if let Role::PartyEval = role {
        for output_party in &output_parties {
            if *output_party != p_own {
                for w in circuit.output_gates.iter().copied() {
                    wires_and_labels[w] = Some((values[w], labels_eval[w][*output_party]));
                }
                parties
                    .send_to(*output_party, "lambda", &wires_and_labels)
                    .await?; // sending (lambda_w XOR zw) to output parties
            }
        }
    } else if let Role::PartyContribOutput = role {
        wires_and_labels = parties.recv_vec_from(p_eval, "lambda", num_gates).await?; //receiving of (lambda_w XOR zw) from evaluator
        for w in circuit.output_gates.iter().copied() {
            if !(wires_and_labels[w] == Some((true, labels[w] ^ delta))
                || wires_and_labels[w] == Some((false, labels[w])))
            {
                return Err(MpcError::InvalidOutputWireLabel(w).into());
            }
        }
    }
    let mut outputs: Vec<bool> = vec![];
    if output_parties.contains(&p_own) {
        let mut output_wires: Vec<Option<bool>> = vec![None; num_gates];
        for w in circuit.output_gates.iter().copied() {
            let Some((input, _)) = wires_and_labels.get(w).copied().flatten() else {
                return Err(MpcError::MissingShareForWire(w).into()); // error type right?
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
