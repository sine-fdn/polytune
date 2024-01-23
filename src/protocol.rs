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

/// A custom error type for all SMPC operations.
#[derive(Debug)]
pub enum MpcError {
    /// No secret share was sent for the specified wire.
    MissingShareForWire(usize),
    /// No AND share was sent for the specified wire.
    MissingAndShareForWire(usize),
    /// The input on the specified wire did not match the message authenatication code.
    InvalidInputMacOnWire(usize),
    /// The specified wire is not an input wire or the input is missing.
    WireWithoutInput(usize),
    /// No garbled gate was sent for the specified wire.
    MissingGarbledGate(usize),
    /// The output on the specified wire did not match the message authenatication code.
    InvalidOutputMacOnWire(usize),
}

impl From<MpcError> for Error {
    fn from(e: MpcError) -> Self {
        Self::MpcError(e)
    }
}

/// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
pub fn simulate_mpc(circuit: &Circuit, inputs: &[&[bool]]) -> Result<Vec<bool>, Error> {
    let n_parties = inputs.len();
    let eval_i = 0;
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

        for (party, ((fpre_channel, party_channel), inputs)) in parties {
            let circuit = circuit.clone();
            let inputs = inputs.to_vec();
            task::spawn(async move {
                if let Err(e) = mpc(
                    &circuit,
                    &inputs,
                    fpre_channel,
                    party_channel,
                    eval_i,
                    party,
                    Role::PartyContrib,
                )
                .await
                {
                    eprintln!("SMPC protocol failed for party A: {:?}", e);
                }
            });
        }
        let (_, ((fpre_channel, party_channel), inputs)) = evaluator;
        mpc(
            circuit,
            inputs,
            fpre_channel,
            party_channel,
            eval_i,
            eval_i,
            Role::PartyEval,
        )
        .await
    })
}

/// The role played by a particular party in the protocol execution.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    /// The party contributes inputs, but does not evaluate the circuit.
    PartyContrib,
    /// The party contributes inputs and evaluates the circuit.
    PartyEval,
}

/// Executes the MPC protocol for one party and returns the outputs (empty for the contributor).
pub async fn mpc<Fpre: Channel, Party: Channel>(
    circuit: &Circuit,
    inputs: &[bool],
    mut fpre: MsgChannel<Fpre>,
    mut parties: MsgChannel<Party>,
    eval_i: usize,
    p_i: usize,
    role: Role,
) -> Result<Vec<bool>, Error> {
    circuit.validate()?;
    let Some(expected_inputs) = circuit.input_gates.get(p_i) else {
        return Err(Error::PartyDoesNotExist);
    };
    if *expected_inputs != inputs.len() {
        return Err(Error::WrongInputSize {
            expected: *expected_inputs,
            actual: inputs.len(),
        });
    }

    let fpre_party = 0;
    let max_i = parties.participants();

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

    let mut wire_shares_and_labels = vec![(Share(false, Auth(vec![])), Label(0)); num_gates];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(_) | Wire::And(_, _) = gate {
            let Some(share) = random_shares.next() else {
                return Err(MpcError::MissingShareForWire(w).into());
            };
            let label = match role {
                Role::PartyContrib => Label(random()),
                // the labels are calculated later by the evaluator, so we just use 0 for now:
                Role::PartyEval => Label(0),
            };
            wire_shares_and_labels[w] = (share, label);
        }
    }

    // fn-dependent preprocessing:

    let mut and_shares = Vec::new();
    for (w, gate) in circuit.wires().iter().enumerate() {
        match gate {
            Wire::Input(_) => {}
            Wire::Not(x) => {
                let (auth_bit, label) = wire_shares_and_labels[*x].clone();
                wire_shares_and_labels[w] = (auth_bit, label ^ delta);
            }
            Wire::Xor(x, y) => {
                let (share_x, label_x) = wire_shares_and_labels[*x].clone();
                let (share_y, label_y) = wire_shares_and_labels[*y].clone();
                wire_shares_and_labels[w] = (&share_x ^ &share_y, label_x ^ label_y);
            }
            Wire::And(x, y) => {
                let (share_x, _) = wire_shares_and_labels[*x].clone();
                let (share_y, _) = wire_shares_and_labels[*y].clone();
                and_shares.push((share_x, share_y));
            }
        }
    }
    fpre.send_to(fpre_party, "AND shares", &and_shares).await?;
    let auth_bits: Vec<Share> = fpre.recv_from(fpre_party, "AND shares").await?;
    let mut auth_bits = auth_bits.into_iter();

    let mut table_shares = vec![None; num_gates];
    let mut garbled_gates: Vec<Vec<Option<GarbledGate>>> = vec![vec![None; num_gates]; max_i];
    if let Role::PartyContrib = role {
        let mut preprocessed_gates = vec![None; num_gates];
        for (w, gate) in circuit.wires().iter().enumerate() {
            if let Wire::And(x, y) = gate {
                let x = wire_shares_and_labels[*x].clone();
                let y = wire_shares_and_labels[*y].clone();
                let gamma = wire_shares_and_labels[w].clone();
                let (Share(r_x, mac_r_x_key_s_x), label_x_0) = x;
                let (Share(r_y, mac_r_y_key_s_y), label_y_0) = y;
                let (Share(r_gamma, mac_r_gamma_key_s_gamma), label_gamma_0) = gamma;
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
                    (&mac_r_key_s_1 ^ &mac_r_y_key_s_y).xor_key(eval_i, delta),
                );

                let label_x_1 = label_x_0 ^ delta;
                let label_y_1 = label_y_0 ^ delta;

                let k0 = GarblingKey::new(label_x_0, label_y_0, w, 0);
                let k1 = GarblingKey::new(label_x_0, label_y_1, w, 1);
                let k2 = GarblingKey::new(label_x_1, label_y_0, w, 2);
                let k3 = GarblingKey::new(label_x_1, label_y_1, w, 3);

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
            .send_to(eval_i, "preprocessed gates", &preprocessed_gates)
            .await?;
    } else {
        for i in (0..max_i).filter(|i| *i != eval_i) {
            garbled_gates[i] = parties.recv_from(i, "preprocessed gates").await?
        }
        for (w, gate) in circuit.wires().iter().enumerate() {
            if let Wire::And(x, y) = gate {
                let (x, _) = wire_shares_and_labels[*x].clone();
                let (y, _) = wire_shares_and_labels[*y].clone();
                let (gamma, _) = wire_shares_and_labels[w].clone();
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
        vec![vec![None; wire_shares_and_labels.len()]; max_i];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(i) = gate {
            if p_i != *i {
                let (Share(bit, Auth(macs_and_keys)), _) = wire_shares_and_labels[w].clone();
                let (mac, _) = macs_and_keys[*i].unwrap();
                wire_shares_for_others[*i][w] = Some((bit, mac));
            }
        }
    }
    for i in (0..max_i).filter(|i| *i != p_i) {
        parties
            .send_to(i, "wire shares", &wire_shares_for_others[i])
            .await?;
    }

    let mut wire_shares_from_others: Vec<Vec<Option<(bool, Mac)>>> =
        vec![vec![None; wire_shares_and_labels.len()]; max_i];
    for i in (0..max_i).filter(|i| *i != p_i) {
        wire_shares_from_others[i] = parties
            .recv_vec_from(i, "wire shares", wire_shares_and_labels.len())
            .await?;
    }

    let mut inputs = inputs.iter();
    let mut masked_inputs: Vec<Option<bool>> = vec![None; wire_shares_and_labels.len()];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(p_input) = gate {
            if p_i == *p_input {
                let Some(input) = inputs.next() else {
                    return Err(MpcError::WireWithoutInput(w).into());
                };
                let (Share(own_share, Auth(own_macs_and_keys)), _) =
                    wire_shares_and_labels[w].clone();
                masked_inputs[w] = Some(*input ^ own_share);
                for i in (0..max_i).filter(|i| *i != p_i) {
                    let (_, key) = own_macs_and_keys[i].unwrap();
                    let (other_share, mac) = wire_shares_from_others[i][w].unwrap();
                    if mac != key ^ (other_share & delta) {
                        return Err(MpcError::InvalidInputMacOnWire(w).into());
                    } else {
                        *masked_inputs[w].as_mut().unwrap() ^= other_share;
                    }
                }
            }
        }
    }
    for i in (0..max_i).filter(|i| *i != p_i) {
        parties.send_to(i, "masked inputs", &masked_inputs).await?;
    }
    for i in (0..max_i).filter(|i| *i != p_i) {
        let masked_inputs_from_other_party: Vec<Option<bool>> = parties
            .recv_vec_from(i, "masked inputs", wire_shares_and_labels.len())
            .await?;
        for (w, mask) in masked_inputs_from_other_party.iter().enumerate() {
            if let Some(mask) = mask {
                if masked_inputs[w].is_some() {
                    panic!("Each input mask should only come from one single party!");
                }
                masked_inputs[w] = Some(*mask);
            }
        }
    }

    let mut input_labels: Vec<Option<Vec<Label>>> = vec![None; wire_shares_and_labels.len()];
    if let Role::PartyContrib = role {
        let labels_of_other_inputs: Vec<Option<Label>> = masked_inputs
            .iter()
            .enumerate()
            .map(|(w, input)| {
                input.map(|input| {
                    let (_, l0) = wire_shares_and_labels[w];
                    if input {
                        l0 ^ delta
                    } else {
                        l0
                    }
                })
            })
            .collect();
        parties
            .send_to(eval_i, "evaluator labels", &labels_of_other_inputs)
            .await?;
    } else {
        for i in (0..max_i).filter(|i| *i != p_i) {
            let labels_of_own_inputs: Vec<Option<Label>> = parties
                .recv_vec_from(i, "{p_i}: evaluator labels", wire_shares_and_labels.len())
                .await?;
            for (w, label) in labels_of_own_inputs.iter().enumerate() {
                if let Some(label) = label {
                    let labels = input_labels[w].get_or_insert(vec![Label(0); max_i]);
                    labels[i] = *label;
                }
            }
        }
    }

    // circuit evaluation:

    let mut values: Vec<bool> = Vec::with_capacity(num_gates);
    if let Role::PartyContrib = role {
        // nothing to do for party A
    } else {
        let mut labels: Vec<Vec<Label>> = Vec::with_capacity(num_gates);
        for (w, gate) in circuit.wires().iter().enumerate() {
            let (input, label) = match gate {
                Wire::Input(_) => {
                    let input =
                        masked_inputs[w].unwrap_or_else(|| panic!("No value for input gate {w}"));
                    let label = input_labels[w]
                        .as_ref()
                        .unwrap_or_else(|| panic!("No label for input gate {w}"));
                    (input, label.clone())
                }
                Wire::Not(x) => {
                    let input = values[*x];
                    let label = &labels[*x];
                    (!input, label.clone())
                }
                Wire::Xor(x, y) => {
                    let input_x = values[*x];
                    let label_x = &labels[*x];
                    let input_y = values[*y];
                    let label_y = &labels[*y];
                    (input_x ^ input_y, xor_labels(label_x, label_y))
                }
                Wire::And(x, y) => {
                    let input_x = values[*x];
                    let label_x = &labels[*x];
                    let input_y = values[*y];
                    let label_y = &labels[*y];
                    let i = 2 * (input_x as usize) + (input_y as usize);
                    let Some(table_shares) = &table_shares[w] else {
                        return Err(MpcError::MissingShareForWire(w).into());
                    };

                    let mut label = vec![Label(0); max_i];
                    let mut macs = vec![vec![]; max_i];
                    let Share(mut s, mac_s_key_r) = table_shares[i].clone();
                    macs[eval_i] = mac_s_key_r.macs();
                    let Auth(mac_s_key_r) = mac_s_key_r;
                    for p in (0..max_i).filter(|i| *i != eval_i) {
                        let Some(GarbledGate(garbled_gate)) = &garbled_gates[p][w] else {
                            return Err(MpcError::MissingGarbledGate(w).into());
                        };
                        let garbling_key = GarblingKey::new(label_x[p], label_y[p], w, i as u8);
                        let garbled_row = garbled_gate[i].clone();
                        let (r, mac_r, label_share) = decrypt(&garbling_key, &garbled_row)?;
                        let (_, key_r) = mac_s_key_r[p].unwrap();
                        if mac_r[eval_i].unwrap() != key_r ^ (r & delta) {
                            return Err(MpcError::InvalidInputMacOnWire(w).into());
                        }
                        s ^= r;
                        label[p] = label_share;
                        macs[p] = mac_r;
                    }
                    for p in (0..max_i).filter(|i| *i != eval_i) {
                        for party in (0..max_i).filter(|i| *i != p) {
                            if let Some(macs) = macs.get(party) {
                                label[p] = label[p] ^ macs[p].unwrap()
                            }
                        }
                    }
                    (s, label)
                }
            };
            values.push(input);
            labels.push(label);
        }
    }

    // output determination:

    if let Role::PartyContrib = role {
        let mut outputs = vec![None; num_gates];
        for w in circuit.output_gates.iter().copied() {
            let (Share(bit, Auth(macs_and_keys)), _) = wire_shares_and_labels[w].clone();
            let (mac, _) = macs_and_keys[eval_i].unwrap();
            outputs[w] = Some((bit, mac));
        }
        parties
            .send_to(eval_i, "output wire shares", &outputs)
            .await?;
        Ok(vec![])
    } else {
        let mut output_wire_shares: Vec<Vec<Option<(bool, Mac)>>> = vec![vec![]; max_i];
        for i in (0..max_i).filter(|i| *i != p_i) {
            output_wire_shares[i] = parties
                .recv_vec_from(i, "output wire shares", values.len())
                .await?;
        }
        let mut output_wires: Vec<Option<bool>> = vec![None; wire_shares_and_labels.len()];
        for w in circuit.output_gates.iter().copied() {
            let input = values[w];
            let (Share(s, _), _) = &wire_shares_and_labels[w];
            output_wires[w] = Some(input ^ s);
        }
        for i in (0..max_i).filter(|i| *i != p_i) {
            for (w, output_wire) in output_wire_shares[i].iter().enumerate() {
                let (Share(_, Auth(mac_s_key_r)), _) = &wire_shares_and_labels[w];
                let (_, key_r) = mac_s_key_r.get(i).copied().unwrap().unwrap();
                if let Some((r, mac_r)) = output_wire {
                    if *mac_r != key_r ^ (*r & delta) {
                        return Err(MpcError::InvalidOutputMacOnWire(w).into());
                    } else {
                        let o = output_wires[w].unwrap();
                        output_wires[w] = Some(o ^ r);
                    }
                }
            }
        }
        let mut outputs = vec![];
        for w in circuit.output_gates.iter() {
            outputs.push(output_wires[*w].unwrap());
        }
        Ok(outputs)
    }
}
