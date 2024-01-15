//! Secure 2-party computation protocol with communication via channels.
use std::{collections::HashSet, ops::BitXor};

use rand::random;
use serde::{Deserialize, Serialize};
use tokio::{runtime::Runtime, task};

use crate::{
    channel::{self, Channel, MsgChannel, SimpleChannel},
    circuit::{self, Circuit, Gate},
    fpre::{f_pre, AuthBit, Delta, Key, Mac},
    hash::{hash, hash_xor_triple},
};

/// The index of a particular wire in a circuit.
pub type Wire = usize;

/// A collection of wire indices.
pub type Wires = HashSet<Wire>;

/// Preprocessed AND gates that need to be sent to the circuit evaluator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GarbledGate(pub [(bool, Mac, Label); 4]);

/// A label for a particular wire in the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label(pub u128);

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
    CircuitError(circuit::Error),
    /// Caused by the core SMPC protocol computation.
    MpcError(MpcError),
}

impl From<circuit::Error> for Error {
    fn from(e: circuit::Error) -> Self {
        Self::CircuitError(e)
    }
}

impl From<channel::Error> for Error {
    fn from(e: channel::Error) -> Self {
        Self::ChannelError(e)
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

/// Simulates the 2-party computation of the specified circuit and inputs.
pub fn simulate_mpc(
    circuit: &Circuit,
    in_a: &[bool],
    in_b: &[bool],
) -> Result<Vec<Option<bool>>, Error> {
    let tokio = Runtime::new().expect("Could not start tokio runtime");
    tokio.block_on(async {
        let (fpre_a, fpre_b) = f_pre().await;
        let (party_a, party_b) = SimpleChannel::channels();

        {
            let circuit = circuit.clone();
            let in_a = in_a.to_vec();
            task::spawn(async move {
                if let Err(e) = mpc(&circuit, &in_a, fpre_a, party_a, Role::PartyContrib).await {
                    eprintln!("SMPC protocol failed for party A: {:?}", e);
                }
            });
        }

        return mpc(circuit, in_b, fpre_b, party_b, Role::PartyEval).await;
    })
}

#[derive(Debug, Clone, Copy)]
enum Role {
    PartyContrib,
    PartyEval,
}

async fn mpc<Fpre: Channel, Party: Channel>(
    circuit: &Circuit,
    inputs: &[bool],
    mut fpre: MsgChannel<Fpre>,
    mut party: MsgChannel<Party>,
    role: Role,
) -> Result<Vec<Option<bool>>, Error> {
    circuit.validate()?;
    if let Role::PartyContrib = role {
        circuit.validate_contributor_input(&inputs)?;
    } else {
        circuit.validate_evaluator_input(&inputs)?;
    }

    // fn-independent preprocessing:

    fpre.send("delta", &()).await?;
    let delta: Delta = fpre.recv("delta").await?;

    let secret_bits = circuit.contrib_inputs() + circuit.eval_inputs() + circuit.and_gates();
    fpre.send("random shares", &(secret_bits as u32)).await?;

    let random_shares: Vec<AuthBit> = fpre.recv("random shares").await?;
    let mut random_shares = random_shares.into_iter();

    let mut wire_shares_and_labels =
        vec![(AuthBit(false, Mac(0), Key(0)), Label(0)); circuit.gates().len()];
    for (w, gate) in circuit.gates().iter().enumerate() {
        if let Gate::InContrib | Gate::InEval | Gate::And(_, _) = gate {
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
    for (w, gate) in circuit.gates().iter().enumerate() {
        match gate {
            Gate::InContrib | Gate::InEval => {}
            Gate::Not(x) => {
                let (auth_bit, label) = wire_shares_and_labels[*x as usize];
                wire_shares_and_labels[w] = (auth_bit, label ^ delta);
            }
            Gate::Xor(x, y) => {
                let (share_x, label_x) = wire_shares_and_labels[*x as usize];
                let (share_y, label_y) = wire_shares_and_labels[*y as usize];
                wire_shares_and_labels[w] = (share_x ^ share_y, label_x ^ label_y);
            }
            Gate::And(x, y) => {
                let (share_x, _) = wire_shares_and_labels[*x as usize];
                let (share_y, _) = wire_shares_and_labels[*y as usize];
                and_shares.push((share_x, share_y));
            }
        }
    }
    fpre.send("AND shares", &and_shares).await?;
    let auth_bits: Vec<AuthBit> = fpre.recv("AND shares").await?;
    let mut auth_bits = auth_bits.into_iter();

    let mut table_shares = vec![None; circuit.gates().len()];
    let mut garbled_gates: Vec<Option<GarbledGate>> = vec![None; circuit.gates().len()];
    if let Role::PartyContrib = role {
        let mut preprocessed_gates = vec![None; circuit.gates().len()];
        for (w, gate) in circuit.gates().iter().enumerate() {
            if let Gate::And(x, y) = gate {
                let x = wire_shares_and_labels[*x as usize];
                let y = wire_shares_and_labels[*y as usize];
                let gamma = wire_shares_and_labels[w];
                let (AuthBit(r_x, mac_r_x, key_s_x), label_x_0) = x;
                let (AuthBit(r_y, mac_r_y, key_s_y), label_y_0) = y;
                let (AuthBit(r_gamma, mac_r_gamma, key_s_gamma), label_gamma_0) = gamma;
                let Some(sigma) = auth_bits.next() else {
                    return Err(MpcError::MissingAndShareForWire(w).into());
                };
                let AuthBit(r_sig, mac_r_sig, key_s_sig) = sigma;
                let r = r_sig ^ r_gamma;
                let mac_r = mac_r_sig ^ mac_r_gamma;
                let key_s = key_s_sig ^ key_s_gamma;
                let row0 = AuthBit(r, mac_r, key_s);
                let row1 = AuthBit(r ^ r_x, mac_r ^ mac_r_x, key_s ^ key_s_x);
                let row2 = AuthBit(r ^ r_y, mac_r ^ mac_r_y, key_s ^ key_s_y);
                let row3 = AuthBit(
                    r ^ r_x ^ r_y,
                    mac_r ^ mac_r_x ^ mac_r_y,
                    key_s ^ key_s_x ^ key_s_y ^ Key(delta.0),
                );

                let label_x_1 = label_x_0 ^ Label(delta.0);
                let label_y_1 = label_y_0 ^ Label(delta.0);

                let h0 = hash(label_x_0, label_y_0, w, 0);
                let h1 = hash(label_x_0, label_y_1, w, 1);
                let h2 = hash(label_x_1, label_y_0, w, 2);
                let h3 = hash(label_x_1, label_y_1, w, 3);

                let row0_label = Label(label_gamma_0.0 ^ (row0.2 .0) ^ (row0.0 & delta).0);
                let row1_label = Label(label_gamma_0.0 ^ (row1.2 .0) ^ (row1.0 & delta).0);
                let row2_label = Label(label_gamma_0.0 ^ (row2.2 .0) ^ (row2.0 & delta).0);
                let row3_label = Label(label_gamma_0.0 ^ (row3.2 .0) ^ (row3.0 & delta).0);

                let garbled0 = hash_xor_triple(&h0, (row0.0, row0.1, row0_label));
                let garbled1 = hash_xor_triple(&h1, (row1.0, row1.1, row1_label));
                let garbled2 = hash_xor_triple(&h2, (row2.0, row2.1, row2_label));
                let garbled3 = hash_xor_triple(&h3, (row3.0, row3.1, row3_label));

                preprocessed_gates[w] = Some(GarbledGate([garbled0, garbled1, garbled2, garbled3]));
            }
        }
        party
            .send("preprocessed gates", &preprocessed_gates)
            .await?;
    } else {
        garbled_gates = party.recv("preprocessed gates").await?;
        for (w, gate) in circuit.gates().iter().enumerate() {
            if let Gate::And(x, y) = gate {
                let (x, _) = wire_shares_and_labels[*x as usize];
                let (y, _) = wire_shares_and_labels[*y as usize];
                let (gamma, _) = wire_shares_and_labels[w];
                let AuthBit(s_x, mac_s_x, key_r_x) = x;
                let AuthBit(s_y, mac_s_y, key_r_y) = y;
                let AuthBit(s_gamma, mac_s_gamma, key_r_gamma) = gamma;
                let Some(sigma) = auth_bits.next() else {
                    return Err(MpcError::MissingAndShareForWire(w).into());
                };
                let AuthBit(s_sig, mac_s_sig, key_r_sig) = sigma;
                let s = s_sig ^ s_gamma;
                let mac_s = mac_s_sig ^ mac_s_gamma;
                let key_r = key_r_sig ^ key_r_gamma;
                let row0 = AuthBit(s, mac_s, key_r);
                let row1 = AuthBit(s ^ s_x, mac_s ^ mac_s_x, key_r ^ key_r_x);
                let row2 = AuthBit(s ^ s_y, mac_s ^ mac_s_y, key_r ^ key_r_y);
                let row3 = AuthBit(
                    s ^ s_x ^ s_y ^ true,
                    mac_s ^ mac_s_x ^ mac_s_y,
                    key_r ^ key_r_x ^ key_r_y,
                );
                table_shares[w] = Some([row0, row1, row2, row3]);
            }
        }
    }

    // input processing:

    let wire_shares_for_other_party: Vec<_> = circuit
        .gates()
        .iter()
        .enumerate()
        .map(|(w, gate)| match (role, gate) {
            (Role::PartyContrib, Gate::InEval) | (Role::PartyEval, Gate::InContrib) => {
                let (AuthBit(bit, mac, _), _) = wire_shares_and_labels[w];
                Some((bit, mac))
            }
            _ => None,
        })
        .collect();
    party
        .send("wire shares", &wire_shares_for_other_party)
        .await?;

    let wire_shares_from_other_party: Vec<Option<(bool, Mac)>> = party
        .recv_vec("wire shares", wire_shares_and_labels.len())
        .await?;

    let mut masked_inputs = vec![None; wire_shares_and_labels.len()];
    if let Role::PartyContrib = role {
        let mut labels_of_own_inputs = vec![None; wire_shares_and_labels.len()];
        let mut inputs = inputs.iter();
        for (w, wire) in wire_shares_from_other_party.into_iter().enumerate() {
            if let Some((s, mac_s)) = wire {
                let (AuthBit(r, _mac_r, key_s), label_0) = wire_shares_and_labels[w];
                let Some(input) = inputs.next() else {
                    return Err(MpcError::WireWithoutInput(w as Wire).into());
                };
                if mac_s != key_s ^ (s & delta) {
                    return Err(MpcError::InvalidInputMacOnWire(w as Wire).into());
                } else {
                    let masked_input = input ^ r ^ s;
                    masked_inputs[w] = Some(masked_input);
                    let label_1 = Label(label_0.0 ^ delta.0);
                    let label = if masked_input { label_1 } else { label_0 };
                    labels_of_own_inputs[w] = Some(label);
                }
            }
        }
        party.send("masked inputs", &masked_inputs).await?;
        party
            .send("contributor labels", &labels_of_own_inputs)
            .await?;
    } else {
        let mut inputs = inputs.iter();
        for (w, wire_a) in wire_shares_from_other_party.into_iter().enumerate() {
            if let Some((r, mac_r)) = wire_a {
                let (AuthBit(s, _mac_s, key_r), _) = wire_shares_and_labels[w];
                let Some(input) = inputs.next() else {
                    return Err(MpcError::WireWithoutInput(w as Wire).into());
                };
                if mac_r != key_r ^ (r & delta) {
                    return Err(MpcError::InvalidInputMacOnWire(w as Wire).into());
                } else {
                    masked_inputs[w] = Some(input ^ r ^ s);
                }
            }
        }
        party.send("masked inputs", &masked_inputs).await?;
    }

    let masked_other_inputs: Vec<Option<bool>> = party
        .recv_vec("masked inputs", wire_shares_and_labels.len())
        .await?;

    let mut input_labels = vec![None; wire_shares_and_labels.len()];
    if let Role::PartyContrib = role {
        let labels_of_other_inputs: Vec<_> = masked_other_inputs
            .into_iter()
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
        party
            .send("evaluator labels", &labels_of_other_inputs)
            .await?;
    } else {
        for (w, input) in masked_other_inputs.into_iter().enumerate() {
            if let Some(input) = input {
                masked_inputs[w] = Some(input);
            }
        }
        let labels_of_other_inputs: Vec<Option<Label>> =
            party.recv_vec("other labels", input_labels.len()).await?;
        for (w, label) in labels_of_other_inputs.into_iter().enumerate() {
            if let Some(label) = label {
                input_labels[w] = Some(label);
            }
        }
        let labels_of_own_inputs: Vec<Option<Label>> = party
            .recv_vec("evaluator labels", input_labels.len())
            .await?;
        for (w, label) in labels_of_own_inputs.into_iter().enumerate() {
            if let Some(label) = label {
                input_labels[w] = Some(label);
            }
        }
    }

    // circuit evaluation:

    let mut values: Vec<bool> = Vec::with_capacity(circuit.gates().len());
    if let Role::PartyContrib = role {
        // nothing to do for party A
    } else {
        let mut labels: Vec<Label> = Vec::with_capacity(circuit.gates().len());
        for (w, gate) in circuit.gates().iter().enumerate() {
            let (input, label) = match gate {
                Gate::InContrib | Gate::InEval => {
                    let input = masked_inputs[w].expect("No value for input gate");
                    let label = input_labels[w].expect("No label for input gate");
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

                    let Some(table_shares) = table_shares[w] else {
                        return Err(MpcError::MissingShareForWire(w).into());
                    };
                    let AuthBit(s, mac_s, key_r) = table_shares[i];
                    let Some(garbled_gate) = garbled_gates[w] else {
                        return Err(MpcError::MissingGarbledGate(w).into());
                    };
                    let hash = hash(label_x, label_y, w, i as u8);
                    let garbled_row = garbled_gate.0[i];
                    let (r, mac_r, label_share) = hash_xor_triple(&hash, garbled_row);
                    if mac_r != key_r ^ (r & delta) {
                        return Err(MpcError::InvalidInputMacOnWire(w).into());
                    } else {
                        let input = r ^ s;
                        let label = Label(label_share.0 ^ mac_s.0);
                        (input, label)
                    }
                }
            };
            values.push(input);
            labels.push(label);
        }
    }

    // output determination:

    if let Role::PartyContrib = role {
        let mut outputs = vec![None; circuit.gates().len()];
        for w in circuit.output_gates() {
            let (AuthBit(bit, mac, _key), _label) = wire_shares_and_labels[*w as usize];
            outputs[*w as usize] = Some((bit, mac));
        }
        party.send("output wire shares", &outputs).await?;
        Ok(vec![])
    } else {
        let output_wire_shares: Vec<Option<(bool, Mac)>> =
            party.recv_vec("output wire shares", values.len()).await?;
        let mut outputs = vec![None; output_wire_shares.len()];
        for (w, output_wire) in output_wire_shares.into_iter().enumerate() {
            if let Some((r, mac_r)) = output_wire {
                let input = values[w];
                let (AuthBit(s, _mac_s, key_r), _) = wire_shares_and_labels[w];
                if mac_r != key_r ^ (r & delta) {
                    return Err(MpcError::InvalidOutputMacOnWire(w as Wire).into());
                } else {
                    outputs[w] = Some(input ^ r ^ s);
                }
            }
        }
        Ok(outputs)
    }
}
