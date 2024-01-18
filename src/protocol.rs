//! Secure 2-party computation protocol with communication via channels.
use std::ops::BitXor;

use garble_lang::circuit::{self, Circuit};
use rand::random;
use serde::{Deserialize, Serialize};
use tokio::{runtime::Runtime, task};

use crate::{
    channel::{self, Channel, MsgChannel, SimpleChannel},
    fpre::{f_pre, only_macs, xor_delta_to_keys, xor_keys, xor_shares, AuthBit, Delta, Mac},
    garble::{self, decrypt, encrypt, GarblingKey},
};

/// The index of a particular wire in a circuit.
pub(crate) type Wire = usize;

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

/// Errors occurring during the validation or the execution of the MPC protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum CircuitError {
    /// The gate with the specified wire contains invalid gate connections.
    InvalidGate(usize),
    /// The specified output gate does not exist in the circuit.
    InvalidOutput(usize),
    /// The circuit does not specify any output gates.
    EmptyOutputs,
    /// The provided circuit has too many gates to be processed.
    MaxCircuitSizeExceeded,
    /// The provided index does not correspond to any party.
    PartyIndexOutOfBounds,
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
    MissingShareForWire(Wire),
    /// No AND share was sent for the specified wire.
    MissingAndShareForWire(Wire),
    /// The input on the specified wire did not match the message authenatication code.
    InvalidInputMacOnWire(Wire),
    /// The specified wire is not an input wire or the input is missing.
    WireWithoutInput(Wire),
    /// No garbled gate was sent for the specified wire.
    MissingGarbledGate(Wire),
    /// The output on the specified wire did not match the message authenatication code.
    InvalidOutputMacOnWire(Wire),
}

impl From<MpcError> for Error {
    fn from(e: MpcError) -> Self {
        Self::MpcError(e)
    }
}

/// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
pub fn simulate_mpc(circuit: &Circuit, inputs: &[&[bool]]) -> Result<Vec<Option<bool>>, Error> {
    let n_parties = inputs.len();
    let eval_i = 0;
    let tokio = Runtime::new().expect("Could not start tokio runtime");
    let parties = SimpleChannel::channels(n_parties);
    tokio.block_on(async {
        let fpre_channels = f_pre(inputs.len()).await;

        let mut parties = fpre_channels
            .into_iter()
            .zip(parties.into_iter())
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
                    n_parties,
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
        return mpc(
            circuit,
            inputs,
            fpre_channel,
            party_channel,
            eval_i,
            n_parties,
            eval_i,
            Role::PartyEval,
        )
        .await;
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
    mut party: MsgChannel<Party>,
    eval_i: usize,
    max_i: usize,
    p_i: usize,
    role: Role,
) -> Result<Vec<Option<bool>>, Error> {
    validate(circuit)?;
    let Some(expected_inputs) = circuit.input_gates.get(p_i as usize) else {
        return Err(Error::PartyDoesNotExist);
    };
    if *expected_inputs != inputs.len() {
        return Err(Error::WrongInputSize {
            expected: *expected_inputs,
            actual: inputs.len(),
        });
    }

    let fpre_party = 0;

    // fn-independent preprocessing:

    fpre.send_to(fpre_party, "delta", &()).await?;
    let delta: Delta = fpre.recv_from(fpre_party, "delta").await?;

    let num_input_gates: usize = circuit.input_gates.iter().sum();
    let num_and_gates = circuit
        .gates
        .iter()
        .filter(|g| matches!(g, circuit::Gate::And(_, _)))
        .count();
    let num_gates = num_input_gates + circuit.gates.len();
    let secret_bits = num_input_gates + num_and_gates;
    fpre.send_to(fpre_party, "random shares", &(secret_bits as u32))
        .await?;

    let random_shares: Vec<AuthBit> = fpre.recv_from(fpre_party, "random shares").await?;
    let mut random_shares = random_shares.into_iter();

    let mut wire_shares_and_labels = vec![(AuthBit(false, vec![]), Label(0)); num_gates];
    for (w, gate) in wires(circuit).iter().enumerate() {
        if let Gate::Input(_) | Gate::And(_, _) = gate {
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
    for (w, gate) in wires(circuit).iter().enumerate() {
        match gate {
            Gate::Input(_) => {}
            Gate::Not(x) => {
                let (auth_bit, label) = wire_shares_and_labels[*x as usize].clone();
                wire_shares_and_labels[w] = (auth_bit, label ^ delta);
            }
            Gate::Xor(x, y) => {
                let (share_x, label_x) = wire_shares_and_labels[*x as usize].clone();
                let (share_y, label_y) = wire_shares_and_labels[*y as usize].clone();
                wire_shares_and_labels[w] = (share_x ^ share_y, label_x ^ label_y);
            }
            Gate::And(x, y) => {
                let (share_x, _) = wire_shares_and_labels[*x as usize].clone();
                let (share_y, _) = wire_shares_and_labels[*y as usize].clone();
                and_shares.push((share_x, share_y));
            }
        }
    }
    fpre.send_to(fpre_party, "AND shares", &and_shares).await?;
    let auth_bits: Vec<AuthBit> = fpre.recv_from(fpre_party, "AND shares").await?;
    let mut auth_bits = auth_bits.into_iter();

    let mut table_shares = vec![None; num_gates];
    let mut garbled_gates: Vec<Vec<Option<GarbledGate>>> = vec![vec![None; num_gates]; max_i];
    if let Role::PartyContrib = role {
        let mut preprocessed_gates = vec![None; num_gates];
        for (w, gate) in wires(circuit).iter().enumerate() {
            if let Gate::And(x, y) = gate {
                let x = wire_shares_and_labels[*x as usize].clone();
                let y = wire_shares_and_labels[*y as usize].clone();
                let gamma = wire_shares_and_labels[w].clone();
                let (AuthBit(r_x, mac_r_x_key_s_x), label_x_0) = x;
                let (AuthBit(r_y, mac_r_y_key_s_y), label_y_0) = y;
                let (AuthBit(r_gamma, mac_r_gamma_key_s_gamma), label_gamma_0) = gamma;
                let Some(sigma) = auth_bits.next() else {
                    return Err(MpcError::MissingAndShareForWire(w).into());
                };
                let AuthBit(r_sig, mac_r_sig_key_s_sig) = sigma;
                let r = r_sig ^ r_gamma;
                let mac_r_key_s_0 = xor_shares(&mac_r_sig_key_s_sig, &mac_r_gamma_key_s_gamma);
                let mac_r_key_s_1 = xor_shares(&mac_r_key_s_0, &mac_r_x_key_s_x);
                let row0 = AuthBit(r, mac_r_key_s_0.clone());
                let row1 = AuthBit(r ^ r_x, mac_r_key_s_1.clone());
                let row2 = AuthBit(r ^ r_y, xor_shares(&mac_r_key_s_0, &mac_r_y_key_s_y));
                let row3 = AuthBit(
                    r ^ r_x ^ r_y,
                    xor_delta_to_keys(xor_shares(&mac_r_key_s_1, &mac_r_y_key_s_y), eval_i, delta),
                );

                let label_x_1 = label_x_0 ^ Label(delta.0);
                let label_y_1 = label_y_0 ^ Label(delta.0);

                let k0 = GarblingKey::new(label_x_0, label_y_0, w, 0);
                let k1 = GarblingKey::new(label_x_0, label_y_1, w, 1);
                let k2 = GarblingKey::new(label_x_1, label_y_0, w, 2);
                let k3 = GarblingKey::new(label_x_1, label_y_1, w, 3);

                let row0_label = Label(label_gamma_0.0 ^ xor_keys(&row0.1).0 ^ (row0.0 & delta).0);
                let row1_label = Label(label_gamma_0.0 ^ xor_keys(&row1.1).0 ^ (row1.0 & delta).0);
                let row2_label = Label(label_gamma_0.0 ^ xor_keys(&row2.1).0 ^ (row2.0 & delta).0);
                let row3_label = Label(label_gamma_0.0 ^ xor_keys(&row3.1).0 ^ (row3.0 & delta).0);

                let garbled0 = encrypt(&k0, (row0.0, only_macs(&row0.1), row0_label))?;
                let garbled1 = encrypt(&k1, (row1.0, only_macs(&row1.1), row1_label))?;
                let garbled2 = encrypt(&k2, (row2.0, only_macs(&row2.1), row2_label))?;
                let garbled3 = encrypt(&k3, (row3.0, only_macs(&row3.1), row3_label))?;

                preprocessed_gates[w] = Some(GarbledGate([garbled0, garbled1, garbled2, garbled3]));
            }
        }
        party
            .send_to(eval_i, "preprocessed gates", &preprocessed_gates)
            .await?;
    } else {
        for i in (0..max_i).filter(|i| *i != eval_i) {
            garbled_gates[i] = party.recv_from(i, "preprocessed gates").await?
        }
        for (w, gate) in wires(circuit).iter().enumerate() {
            if let Gate::And(x, y) = gate {
                let (x, _) = wire_shares_and_labels[*x as usize].clone();
                let (y, _) = wire_shares_and_labels[*y as usize].clone();
                let (gamma, _) = wire_shares_and_labels[w].clone();
                let AuthBit(s_x, mac_s_x_key_r_x) = x;
                let AuthBit(s_y, mac_s_y_key_r_y) = y;
                let AuthBit(s_gamma, mac_s_gamma_key_r_gamma) = gamma;
                let Some(sigma) = auth_bits.next() else {
                    return Err(MpcError::MissingAndShareForWire(w).into());
                };
                let AuthBit(s_sig, mac_s_sig_key_r_sig) = sigma;
                let s = s_sig ^ s_gamma;
                let mac_s_key_r_0 = xor_shares(&mac_s_sig_key_r_sig, &mac_s_gamma_key_r_gamma);
                let mac_s_key_r_1 = xor_shares(&mac_s_key_r_0, &mac_s_x_key_r_x);
                let row0 = AuthBit(s, mac_s_key_r_0.clone());
                let row1 = AuthBit(s ^ s_x, mac_s_key_r_1.clone());
                let row2 = AuthBit(s ^ s_y, xor_shares(&mac_s_key_r_0, &mac_s_y_key_r_y));
                let row3 = AuthBit(
                    s ^ s_x ^ s_y ^ true,
                    xor_shares(&mac_s_key_r_1, &mac_s_y_key_r_y),
                );
                table_shares[w] = Some([row0, row1, row2, row3]);
            }
        }
    }

    // input processing:

    let mut wire_shares_for_others: Vec<Vec<Option<(bool, Mac)>>> =
        vec![vec![None; wire_shares_and_labels.len()]; max_i];
    for (w, gate) in wires(circuit).iter().enumerate() {
        if let Gate::Input(i) = gate {
            if p_i != *i {
                let (AuthBit(bit, macs_and_keys), _) = wire_shares_and_labels[w].clone();
                let (mac, _) = macs_and_keys[*i].unwrap();
                wire_shares_for_others[*i][w] = Some((bit, mac));
            }
        }
    }
    for i in (0..max_i).filter(|i| *i != p_i) {
        party
            .send_to(i, "wire shares", &wire_shares_for_others[i])
            .await?;
    }

    let mut wire_shares_from_others: Vec<Vec<Option<(bool, Mac)>>> =
        vec![vec![None; wire_shares_and_labels.len()]; max_i];
    for i in (0..max_i).filter(|i| *i != p_i) {
        wire_shares_from_others[i] = party
            .recv_vec_from(i, "wire shares", wire_shares_and_labels.len())
            .await?;
    }

    let mut masked_inputs = vec![None; wire_shares_and_labels.len()];
    if let Role::PartyContrib = role {
        let mut labels_of_own_inputs: Vec<Vec<Option<Label>>> = vec![vec![]; max_i];
        for i in (0..max_i).filter(|i| *i != p_i) {
            labels_of_own_inputs[i] = vec![None; wire_shares_and_labels.len()];
            let mut inputs = inputs.iter();
            for (w, wire) in wire_shares_from_others[i].iter().enumerate() {
                if let Some((s, mac_s)) = wire {
                    let Some(input) = inputs.next() else {
                        return Err(MpcError::WireWithoutInput(w as Wire).into());
                    };
                    let (AuthBit(r, mac_r_key_s), label_0) = wire_shares_and_labels[w].clone();
                    let Some((_, key_s)) = mac_r_key_s.get(i).copied().unwrap_or(None) else {
                        todo!()
                    };
                    if *mac_s != key_s ^ (*s & delta) {
                        return Err(MpcError::InvalidInputMacOnWire(w as Wire).into());
                    } else {
                        let masked_input = input ^ r ^ s;
                        masked_inputs[w] = Some(masked_input);
                        let label_1 = Label(label_0.0 ^ delta.0);
                        let label = if masked_input { label_1 } else { label_0 };
                        labels_of_own_inputs[i][w] = Some(label);
                    }
                }
            }
            party.send_to(i, "masked inputs", &masked_inputs).await?;
        }
        party
            .send_to(eval_i, "contributor labels", &labels_of_own_inputs)
            .await?;
    } else {
        for i in (0..max_i).filter(|i| *i != p_i) {
            let mut inputs = inputs.iter();
            for (w, wire_a) in wire_shares_from_others[i].iter().enumerate() {
                if let Some((r, mac_r)) = wire_a {
                    let (AuthBit(s, mac_s_key_r), _) = wire_shares_and_labels[w].clone();
                    let Some(input) = inputs.next() else {
                        return Err(MpcError::WireWithoutInput(w as Wire).into());
                    };
                    let Some((_, key_r)) = mac_s_key_r.get(i).copied().unwrap_or(None) else {
                        todo!()
                    };
                    if *mac_r != key_r ^ (*r & delta) {
                        return Err(MpcError::InvalidInputMacOnWire(w as Wire).into());
                    } else {
                        masked_inputs[w] = Some(input ^ r ^ s);
                    }
                }
            }
            party.send_to(i, "masked inputs", &masked_inputs).await?;
        }
    }

    let mut masked_other_inputs: Vec<Vec<Option<bool>>> = vec![vec![]; max_i];
    for i in (0..max_i).filter(|i| *i != p_i) {
        masked_other_inputs[i] = party
            .recv_vec_from(i, "masked inputs", wire_shares_and_labels.len())
            .await?;
    }

    let mut input_labels = vec![None; wire_shares_and_labels.len()];
    if let Role::PartyContrib = role {
        let mut labels_of_other_inputs: Vec<Vec<Option<Label>>> = vec![vec![]; max_i];
        for i in (0..max_i).filter(|i| *i != p_i) {
            labels_of_other_inputs[i] = masked_other_inputs[i]
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
        }
        party
            .send_to(eval_i, "evaluator labels", &labels_of_other_inputs)
            .await?;
    } else {
        for i in (0..max_i).filter(|i| *i != p_i) {
            for (w, input) in masked_other_inputs[i].iter().enumerate() {
                if let Some(input) = input {
                    masked_inputs[w] = Some(*input);
                }
            }
            let labels_of_other_inputs: Vec<Vec<Option<Label>>> =
                party.recv_vec_from(i, "contributor labels", max_i).await?;
            for i in 0..max_i {
                for (w, label) in labels_of_other_inputs[i].iter().enumerate() {
                    if let Some(label) = label {
                        input_labels[w] = Some(*label);
                    }
                }
            }
            let labels_of_own_inputs: Vec<Vec<Option<Label>>> = party
                .recv_vec_from(i, "{p_i}: evaluator labels", max_i)
                .await?;
            for i in 0..max_i {
                for (w, label) in labels_of_own_inputs[i].iter().enumerate() {
                    if let Some(label) = label {
                        input_labels[w] = Some(*label);
                    }
                }
            }
        }
    }
    if p_i == eval_i {
        println!("{p_i}: input labels: {input_labels:#?}");
    }

    // circuit evaluation:

    let mut values: Vec<bool> = Vec::with_capacity(num_gates);
    if let Role::PartyContrib = role {
        // nothing to do for party A
    } else {
        let mut labels: Vec<Label> = Vec::with_capacity(num_gates);
        for (w, gate) in wires(circuit).iter().enumerate() {
            let (input, label) = match gate {
                Gate::Input(_) => {
                    let input =
                        masked_inputs[w].unwrap_or_else(|| panic!("No value for input gate {w}"));
                    let label =
                        input_labels[w].unwrap_or_else(|| panic!("No label for input gate {w}"));
                    (input, label)
                }
                Gate::Not(x) => {
                    let input = values[*x as usize];
                    let label = labels[*x as usize];
                    (!input, label)
                }
                Gate::Xor(x, y) => {
                    let input_x = values[*x as usize];
                    let label_x = labels[*x as usize];
                    let input_y = values[*y as usize];
                    let label_y = labels[*y as usize];
                    (input_x ^ input_y, label_x ^ label_y)
                }
                Gate::And(x, y) => {
                    let input_x = values[*x as usize];
                    let label_x = labels[*x as usize];
                    let input_y = values[*y as usize];
                    let label_y = labels[*y as usize];
                    let i = 2 * (input_x as usize) + (input_y as usize);
                    let Some(table_shares) = &table_shares[w] else {
                        return Err(MpcError::MissingShareForWire(w).into());
                    };
                    let AuthBit(mut s, mac_s_key_r) = table_shares[i].clone();
                    let mut label = 0;

                    for p in (0..max_i).filter(|i| *i != eval_i) {
                        let Some(garbled_gate) = &garbled_gates[p][w] else {
                            return Err(MpcError::MissingGarbledGate(w).into());
                        };
                        let garbling_key = GarblingKey::new(label_x, label_y, w, i as u8);
                        let garbled_row = garbled_gate.0[i].clone();
                        let (r, mac_r, label_share) = decrypt(&garbling_key, &garbled_row)?;

                        label ^= label_share.0;
                        for party in [1] {
                            let mac_r = mac_r[p_i].unwrap();
                            let (mac_s, key_r) = mac_s_key_r[party].unwrap();
                            if mac_r != key_r ^ (r & delta) {
                                return Err(MpcError::InvalidInputMacOnWire(w).into());
                            }
                            label ^= mac_s.0;
                        }
                        s ^= r;
                    }
                    (s, Label(label))
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
            let (AuthBit(bit, macs_and_keys), _) = wire_shares_and_labels[w].clone();
            let (mac, _) = macs_and_keys[eval_i].unwrap();
            outputs[w] = Some((bit, mac));
        }
        party
            .send_to(eval_i, "output wire shares", &outputs)
            .await?;
        Ok(vec![])
    } else {
        let mut output_wire_shares: Vec<Vec<Option<(bool, Mac)>>> = vec![vec![]; max_i];
        for i in (0..max_i).filter(|i| *i != p_i) {
            output_wire_shares[i] = party
                .recv_vec_from(i, "output wire shares", values.len())
                .await?;
        }
        let mut outputs: Vec<Option<bool>> = vec![None; wire_shares_and_labels.len()];
        for w in circuit.output_gates.iter().copied() {
            let input = values[w];
            let (AuthBit(s, _), _) = &wire_shares_and_labels[w];
            outputs[w] = Some(input ^ s);
        }
        for i in (0..max_i).filter(|i| *i != p_i) {
            for (w, output_wire) in output_wire_shares[i].iter().enumerate() {
                let (AuthBit(_, mac_s_key_r), _) = &wire_shares_and_labels[w];
                let Some((_, key_r)) = mac_s_key_r.get(i).copied().unwrap_or(None) else {
                    todo!()
                };
                if let Some((r, mac_r)) = output_wire {
                    if *mac_r != key_r ^ (*r & delta) {
                        return Err(MpcError::InvalidOutputMacOnWire(w as Wire).into());
                    } else {
                        let o = outputs[w].unwrap();
                        outputs[w] = Some(o ^ r);
                    }
                }
            }
        }
        Ok(outputs)
    }
}

const MAX_GATES: usize = (u32::MAX >> 4) as usize;
const MAX_AND_GATES: usize = (u32::MAX >> 8) as usize;

enum Gate {
    Input(usize),
    Xor(usize, usize),
    And(usize, usize),
    Not(usize),
}

fn wires(circuit: &Circuit) -> Vec<Gate> {
    let mut gates = vec![];
    for (party, inputs) in circuit.input_gates.iter().enumerate() {
        for _ in 0..*inputs {
            gates.push(Gate::Input(party))
        }
    }
    for gate in circuit.gates.iter() {
        let gate = match gate {
            circuit::Gate::Xor(x, y) => Gate::Xor(*x, *y),
            circuit::Gate::And(x, y) => Gate::And(*x, *y),
            circuit::Gate::Not(x) => Gate::Not(*x),
        };
        gates.push(gate);
    }
    gates
}

fn validate(circuit: &Circuit) -> Result<(), CircuitError> {
    let mut num_and_gates = 0;
    let wires = wires(circuit);
    for (i, g) in wires.iter().enumerate() {
        match g {
            Gate::Input(_) => {}
            &Gate::Xor(x, y) => {
                if x >= i || y >= i {
                    return Err(CircuitError::InvalidGate(i));
                }
            }
            &Gate::And(x, y) => {
                if x >= i || y >= i {
                    return Err(CircuitError::InvalidGate(i));
                }
                num_and_gates += 1;
            }
            &Gate::Not(x) => {
                if x >= i {
                    return Err(CircuitError::InvalidGate(i));
                }
            }
        }
    }
    if circuit.output_gates.is_empty() {
        return Err(CircuitError::EmptyOutputs);
    }
    for &o in circuit.output_gates.iter() {
        if o >= wires.len() {
            return Err(CircuitError::InvalidOutput(o));
        }
    }
    if num_and_gates > MAX_AND_GATES {
        return Err(CircuitError::MaxCircuitSizeExceeded);
    }
    if wires.len() > MAX_GATES {
        return Err(CircuitError::MaxCircuitSizeExceeded);
    }
    Ok(())
}
