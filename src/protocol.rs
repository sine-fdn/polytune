//! The [WRK17b](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979) protocol, implementing
//! maliciously-secure MPC using garbled circuits.
//!
//! This module provides the core execution engine of Polytune, orchestrating secure computation
//! between multiple parties without revealing their private inputs. The implementation uses
//! authenticated shares and cryptographic primitives to ensure security against malicious
//! adversaries.
//!
//! # Key Features
//!
//! - Malicious security against adversaries who may deviate from the protocol
//! - Garbled circuit approach with authenticated inputs and outputs
//! - Support for both trusted dealer and distributed preprocessing
//! - Comprehensive error handling for protocol violations
//! - Channel-based abstraction for inter-party communication
//!
//! # Protocol Workflow
//!
//! The MPC protocol consists of five main phases:
//!
//! 1. Function-independent preprocessing: Generates correlated randomness needed by all parties
//! 2. Function-dependent preprocessing: Prepares secret shares and garbled gates for AND operations
//! 3. Input processing: Handles secure sharing and masking of private inputs from all parties
//! 4. Circuit evaluation: Performed by the designated evaluator party or parties
//! 5. Output determination: Reveals computation results only to designated output parties
//!
//! # Primary API
//!
//! The main entry point is the [`mpc`] function, which should be called by each participating party
//! with their respective private inputs and party identifiers. The function handles all
//! communication and protocol steps, returning the computation result to authorized output parties.
//!
//! Security is enforced through message authentication codes (MACs), delta-based key generation,
//! and comprehensive verification of all protocol steps.

use garble_lang::circuit::{Circuit, CircuitError, Wire};
use maybe_async::maybe_async;
use rand::{random, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::{
    channel::{self, recv_from, recv_vec_from, send_to, Channel},
    data_types::{Auth, Delta, GarbledGate, Key, Label, Mac, Share},
    faand::{self, beaver_aand, broadcast, bucket_size, fashare, shared_rng_pairwise},
    garble::{self, decrypt, encrypt, GarblingKey},
};

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

/// A custom error type for all steps of the main MPC protocol.
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

/// Specifies how correlated randomness is provided in the prepocessing phase.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum Preprocessor {
    /// Correlated randomness is provided by the (semi-)trusted party with the given index.
    TrustedDealer(usize),
    /// The preprocessing is done using OT extension among the parties, no third party necessary.
    Untrusted,
}

/// Executes the Secure Multi-Party Computation (MPC) protocol for a single party.
///
/// This function implements a garbled circuit-based MPC protocol where parties cooperatively
/// compute a function without revealing their private inputs. The protocol consists of several
/// phases: preprocessing, input processing, circuit evaluation, and output determination.
///
/// # Arguments
///
/// * `channel` - Communication channel to interact with other parties
/// * `circuit` - The Boolean circuit to be evaluated in the MPC protocol
/// * `inputs` - The party's private boolean input bits
/// * `p_eval` - Index of the party that will evaluate the garbled circuit
/// * `p_own` - Index of the current party executing this function
/// * `p_out` - Indices of parties that will receive the computation output
///
/// # Returns
///
/// A vector of boolean values representing the computation result, or an error if the protocol
/// fails.
///
/// # Errors
///
/// Returns `Error` if:
/// - The circuit is invalid
/// - Party indices are invalid
/// - Input size doesn't match circuit expectations
/// - Communication with other parties fails
/// - Protocol-specific errors occur during execution (authentication failures, missing shares,
///   etc.)
///
/// # Protocol Overview
///
/// The protocol proceeds through the following phases:
/// 1. Function-independent preprocessing: generates correlated randomness needed by all parties
/// 2. Function-dependent preprocessing: prepares secret shares and garbled gates for AND operations
/// 3. Input processing: handles sharing and masking of private inputs
/// 4. Circuit evaluation: performed by the evaluator party only
/// 5. Output determination: reveals the computation result to designated output parties
#[maybe_async(AFIT)]
pub async fn mpc(
    channel: &mut impl Channel,
    circuit: &Circuit,
    inputs: &[bool],
    p_eval: usize,
    p_own: usize,
    p_out: &[usize],
) -> Result<Vec<bool>, Error> {
    let p_fpre = Preprocessor::Untrusted;
    _mpc(channel, circuit, inputs, p_fpre, p_eval, p_own, p_out).await
}

#[maybe_async(AFIT)]
pub(crate) async fn _mpc(
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

    let b = bucket_size(num_and_gates);
    let lprime = num_and_gates * b;

    let delta: Delta;
    let mut shared_rand: rand_chacha::ChaCha20Rng = ChaCha20Rng::from_entropy();
    let random_shares: Vec<Share>;
    let mut xyz_shares = vec![];

    if let Preprocessor::TrustedDealer(p_fpre) = p_fpre {
        send_to::<()>(channel, p_fpre, "delta", &[]).await?;
        delta = recv_from(channel, p_fpre, "delta")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;

        send_to(channel, p_fpre, "random shares", &[secret_bits as u32]).await?;
        random_shares = recv_vec_from(channel, p_fpre, "random shares", secret_bits).await?;
    } else {
        delta = Delta(random());
        let shared_two_by_two = shared_rng_pairwise(channel, p_own, p_max).await?;

        let (rand_shares, multi_shared_rand) = fashare(
            (channel, delta),
            p_own,
            p_max,
            secret_bits + 3 * lprime,
            shared_two_by_two,
        )
        .await?;
        shared_rand = multi_shared_rand;

        let (random_shares_vec, xyzbits_vec) = rand_shares.split_at(secret_bits);
        random_shares = random_shares_vec.to_vec();
        xyz_shares = xyzbits_vec.to_vec();
    }

    let mut random_shares = random_shares.into_iter();
    let mut shares = vec![Share(false, Auth(vec![])); num_gates];
    let mut labels = vec![Label(0); num_gates];

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

    let mut auth_bits: Vec<Share> = vec![];
    if let Preprocessor::TrustedDealer(p_fpre) = p_fpre {
        send_to(channel, p_fpre, "AND shares", &and_shares).await?;
        auth_bits = recv_vec_from(channel, p_fpre, "AND shares", num_and_gates).await?;
    } else if !xyz_shares.is_empty() {
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

    let mut wire_shares_for_others = vec![vec![None; num_gates]; p_max];
    for (w, gate) in circuit.wires().iter().enumerate() {
        if let Wire::Input(i) = gate {
            let Share(bit, Auth(macs_and_keys)) = shares[w].clone();
            let Some((mac, _)) = macs_and_keys.get(*i) else {
                return Err(MpcError::MissingSharesForInput(*i).into());
            };
            if *mac != Mac(0) {
                wire_shares_for_others[*i][w] = Some((bit, *mac));
            }
        }
    }
    for p in (0..p_max).filter(|p| *p != p_own) {
        send_to(channel, p, "wire shares", &wire_shares_for_others[p]).await?;
    }

    let mut wire_shares_from_others = vec![vec![None; num_gates]; p_max];
    for p in (0..p_max).filter(|p| *p != p_own) {
        wire_shares_from_others[p] =
            recv_vec_from::<Option<(bool, Mac)>>(channel, p, "wire shares", num_gates).await?;
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
                    if let Some((_, key)) = own_macs_and_keys.get(p).copied() {
                        if key != Key(0) {
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
                }
                masked_inputs[w] = Some(masked_input)
            }
        }
    }
    let masked_inputs_from_other_party = broadcast(
        channel,
        p_own,
        p_max,
        "masked inputs",
        &masked_inputs,
        num_gates,
    )
    .await?;

    for p in (0..p_max).filter(|p| *p != p_own) {
        for (w, mask) in masked_inputs_from_other_party[p].iter().enumerate() {
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
                        let (_, key_r) = mac_s_key_r;
                        if *key_r == Key(0) {
                            continue;
                        }
                        let Some(GarbledGate(garbled_gate)) = &garbled_gates[p][w] else {
                            return Err(MpcError::MissingGarbledGate(w).into());
                        };
                        let garbling_key = GarblingKey::new(label_x[p], label_y[p], w, i as u8);
                        let garbled_row = garbled_gate[i].clone();
                        let (r, mac_r, label_share) = decrypt(&garbling_key, &garbled_row)?;
                        let Some(mac_r_for_eval) = mac_r.get(p_eval).copied() else {
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
                                if let Some(mac) = macs.get(p_i).copied() {
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
            if let Some((mac, _)) = macs_and_keys.get(p_out).copied() {
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
                let Some((_, key_r)) = mac_s_key_r.get(p).copied() else {
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
