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
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::iter;
use std::path::Path;
use std::time::Instant;
use std::{cmp, sync::Mutex};

use futures_util::future::{try_join, try_join_all};
use garble_lang::register_circuit::CircuitError;
use garble_lang::register_circuit::{And, Circuit, Input, Not, Op, Reg, Xor};
use rand::random;
use rand_chacha::ChaCha20Rng;
use tracing::{Level, debug, info, instrument};

use crate::block::Block;
use crate::utils::file_or_mem_buf::FileOrMemBuf;
use crate::{
    channel::{self, Channel, recv_from, recv_vec_from, scatter, send_to},
    mpc::{
        data_types::{Auth, Delta, GarbledGate, Label, Mac, Share},
        faand::{
            self, beaver_aand, broadcast, bucket_size, fashare, shared_rng, shared_rng_pairwise,
        },
        garble::{self, GarblingKey, decrypt, encrypt},
    },
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
    /// An error occured while using a temporary file.
    TempFile(std::io::Error),
    /// An error occured while serializing to/deserializing from a temporary file.
    TempFileSerDe(Box<dyn std::error::Error + Send + Sync + 'static>),
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
            Error::TempFile(e) => {
                write!(f, "An error occured while using a temporary file: {e:?}")
            }
            Error::TempFileSerDe(e) => write!(
                f,
                "An error occured while serializing to/deserializing from a temporary file: {e:?}",
            ),
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

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::TempFile(e)
    }
}

impl From<bincode::error::EncodeError> for Error {
    fn from(e: bincode::error::EncodeError) -> Self {
        Self::TempFileSerDe(Box::new(e))
    }
}

impl From<bincode::error::DecodeError> for Error {
    fn from(e: bincode::error::DecodeError) -> Self {
        Self::TempFileSerDe(Box::new(e))
    }
}

/// A custom error type for all steps of the main MPC protocol.
#[derive(Debug)]
pub enum MpcError {
    /// No secret share was sent during preprocessing for the specified instruction.
    MissingPreprocessingShareForInst(usize),
    /// No secret share was sent in the garbled table for the specified instruction.
    MissingTableShareForInst(usize),
    /// No secret share was sent for the specified output register.
    MissingOutputShareForOutReg(Reg),
    /// No AND share was sent for the specified instruction.
    MissingAndShareForInst(usize),
    /// No share was sent for the input instruction, possibly because there are fewer parties than inputs.
    MissingSharesForInput(Input),
    /// The input for the specified instruction did not match the message authentication code.
    InvalidInputMacForInst(usize),
    /// Two different parties tried to provide an input mask for the input instruction.
    ConflictingInputMask(usize),
    /// The specified instruction is not an input or the input is missing.
    InstWithoutInput(usize),
    /// No (masked) value was sent for the input instruction.
    InputWithoutValue(usize),
    /// No label was sent for the input instruction.
    InputWithoutLabel(usize),
    /// No garbled gate was sent for the specified instruction.
    MissingGarbledGate(usize),
    /// The output for the specified output register did not match the message authentication code.
    InvalidOutputMac(Reg),
    /// The output party received a wrong label from the evaluator.
    InvalidOutputLabel(Reg),
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
/// When an optional `tmp_dir` path is provided, Polytune will create temporary files in the
/// specified directory to reduce the peak memory consumption of the protocol evaluation.
/// Note that files created under `/tmp` on many Linux systems are stored in a
/// [tmpfs](https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html) which will not
/// actually write the files to disk. We recommend creating a temporary directory for example
/// in `/var/tmp`.
///
/// # Arguments
///
/// * `channel` - Communication channel to interact with other parties
/// * `circuit` - The Boolean circuit to be evaluated in the MPC protocol
/// * `inputs` - The party's private boolean input bits
/// * `p_eval` - Index of the party that will evaluate the garbled circuit
/// * `p_own` - Index of the current party executing this function
/// * `p_out` - Indices of parties that will receive the computation output
/// * `tmp_dir` - An optional directory path where Polytune will store
///   indermediate data if provided. This improves peak memory consumption.
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
///
/// # Gates and Instructions Terminology
///
/// MPC protocols such as the [WRK17b](https://dl.acm.org/doi/pdf/10.1145/3133956.3133979) protocol
/// are often described as operations on a circuit consisting of gates and wires. This circuit is
/// never actually built in hardware. The terminology is a result of these protocols operating on
/// a directed acyclic graph of basic logic operations (AND, XOR, NOT), i.e., a circuit. These gates
/// are iterated in topological order and executed according to the protocol. In a way, the circuit
/// is similar to a (very restricted) domain specific bytecode for an MPC engine or virtual machine.
///
/// In Garble and Polytune, we use this view and execute a [`Circuit`] consisting of
/// [instructions](`garble_lang::register_circuit::Inst`)
/// and input/output [registers](`Reg`) corresponding to [gates](`garble_lang::circuit::Gate`) and
/// [wires](`garble_lang::circuit::Wire`). The primary benefit is that instructions specifically
/// denote their output register, which can be reused once the stored value is not needed anymore
/// during the execution. This reduces the memory consumption of the MPC evaluation.
#[instrument(level=Level::INFO, skip_all, fields(
    party_id = p_own
))]
pub async fn mpc(
    channel: &impl Channel,
    circuit: &Circuit,
    inputs: &[bool],
    p_eval: usize,
    p_own: usize,
    p_out: &[usize],
    tmp_dir: Option<&Path>,
) -> Result<Vec<bool>, Error> {
    let p_fpre = Preprocessor::Untrusted;
    let ctx = Context::new(
        channel, circuit, inputs, p_fpre, p_eval, p_own, p_out, tmp_dir,
    );
    _mpc(&ctx).await
}

pub(crate) struct Context<'circ, 'inp, 'out, 'ch, 'p, C: Channel> {
    channel: &'ch C,
    circ: &'circ Circuit,
    inputs: &'inp [bool],
    is_contrib: bool,
    p_fpre: Preprocessor,
    p_eval: usize,
    p_own: usize,
    p_max: usize,
    p_out: &'out [usize],
    num_and_ops: usize,
    num_inputs: usize,
    tmp_dir: Option<&'p Path>,
}

impl<'circ, 'inp, 'out, 'ch, 'p, C: Channel> Context<'circ, 'inp, 'out, 'ch, 'p, C> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        channel: &'ch C,
        circ: &'circ Circuit,
        inputs: &'inp [bool],
        p_fpre: Preprocessor,
        p_eval: usize,
        p_own: usize,
        p_out: &'out [usize],
        tmp_dir: Option<&'p Path>,
    ) -> Self {
        let p_max = circ.input_regs.len();
        let is_contrib = p_own != p_eval;
        let num_inputs: usize = circ.input_regs.iter().sum();
        Self {
            channel,
            circ,
            inputs,
            is_contrib,
            p_fpre,
            p_eval,
            p_own,
            p_max,
            p_out,
            num_and_ops: circ.and_ops,
            num_inputs,
            tmp_dir,
        }
    }

    fn random_shares_batch_size(&self) -> usize {
        let random_shares = self.num_inputs + self.num_and_ops;
        cmp::min(
            random_shares,
            cmp::max(random_shares.div_ceil(3 * 3), 1_000),
        )
    }

    fn and_share_batch_size(&self) -> usize {
        // Generate the authenticated bits in batches. This reduces peak memory consumption,
        // because, for each authenticated bit, we need 3 * b random shares. E.g. for 1M
        // auth bits, we need 9M random Shares (b = 3).
        // The minimum batch size is 1k or inputs + and_ops. For small circuits it does not make sense to go lower.
        // TODO choose correct batch_size?
        cmp::min(
            self.num_and_ops,
            cmp::max(self.num_and_ops.div_ceil(3 * 3), 1_000),
        )
    }
}

pub(crate) async fn _mpc(
    ctx: &Context<'_, '_, '_, '_, '_, impl Channel>,
) -> Result<Vec<bool>, Error> {
    let now = Instant::now();
    debug!(
        "MPC protocol execution with {} parties, of which output parties have indices {:?} and the circuit has {} AND gates",
        ctx.p_max, ctx.p_out, ctx.num_and_ops
    );
    validate(ctx)?;
    // fn-independent preprocessing:
    let (delta, mut random_shares, shared_two_by_two, multi_shared_rand) =
        fn_independent_pre(ctx).await?;

    // fn-dependent preprocessing:
    let and_shares = init_and_shares(ctx, &mut random_shares)?;
    let auth_bits =
        gen_auth_bits(ctx, delta, and_shares, shared_two_by_two, multi_shared_rand).await?;
    let (table_shares, garbled_gates, shares, labels, input_labels) =
        garble(ctx, delta, auth_bits, &mut random_shares).await?;

    debug!("Preprocessing phase completed successfully");

    // input processing:
    let (masked_inputs, input_labels) =
        input_processing(ctx, delta, &input_labels, &mut random_shares).await?;

    // circuit evaluation:
    let (values, labels_eval) = evaluate(
        ctx,
        delta,
        table_shares,
        garbled_gates,
        masked_inputs,
        input_labels,
    )?;

    // output determination:
    let outputs = output(ctx, delta, shares, labels, values, labels_eval).await?;

    info!(
        elapsed = ?now.elapsed(),
        and_ops = ctx.num_and_ops,
        total_ops = ctx.circ.insts.len(),
        "MPC protocol execution completed successfully",
    );
    Ok(outputs)
}

#[instrument(level=Level::DEBUG, skip(ctx), err)]
fn validate(ctx: &Context<impl Channel>) -> Result<(), Error> {
    let &Context {
        p_own,
        p_max,
        circ,
        inputs,
        p_out,
        ..
    } = ctx;
    circ.validate()?;
    let Some(expected_inputs) = circ.input_regs.get(p_own) else {
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

    Ok(())
}

// TODO Consider optimizing type complexity of Result here
#[allow(clippy::type_complexity)]
#[instrument(level=Level::DEBUG, skip(ctx), err)]
async fn fn_independent_pre(
    ctx: &Context<'_, '_, '_, '_, '_, impl Channel>,
) -> Result<
    (
        Delta,
        FileOrMemBuf<Share>,
        Option<Vec<Vec<Option<ChaCha20Rng>>>>,
        Option<ChaCha20Rng>,
    ),
    Error,
> {
    let &Context {
        channel,
        p_fpre,
        p_own,
        p_max,
        num_and_ops,
        num_inputs,
        ..
    } = ctx;
    let secret_bits = num_inputs + num_and_ops;
    let delta: Delta;
    let mut random_shares: FileOrMemBuf<Share>;
    let mut shared_two_by_two = None;
    let mut multi_shared_rand = None;
    if let Preprocessor::TrustedDealer(p_fpre) = p_fpre {
        debug!("Using trusted dealer for preprocessing to receive delta and random shares");
        send_to::<()>(channel, p_fpre, "delta", &[]).await?;
        delta = recv_from(channel, p_fpre, "delta")
            .await?
            .pop()
            .ok_or(Error::EmptyMsg)?;

        send_to(channel, p_fpre, "random shares", &[secret_bits as u32]).await?;
        let fpre_shares = recv_vec_from(channel, p_fpre, "random shares", secret_bits).await?;
        random_shares = FileOrMemBuf::Memory { data: fpre_shares };
    } else {
        debug!("Using preprocessing without trusted dealer, generating delta and random shares");
        random_shares = FileOrMemBuf::new(ctx.tmp_dir, secret_bits)?;
        delta = Delta(random());
        shared_two_by_two = Some(shared_rng_pairwise(channel, p_own, p_max).await?);
        multi_shared_rand = Some(shared_rng(channel, p_own, p_max).await?);
        for chunk_size in chunk_size_iter(secret_bits, ctx.random_shares_batch_size()) {
            let chunk_random_shares = fashare(
                (channel, delta),
                p_own,
                p_max,
                chunk_size,
                shared_two_by_two.as_mut().expect("Set above"),
                multi_shared_rand.as_mut().expect("Set above"),
            )
            .await?;
            random_shares.write_chunk(&chunk_random_shares)?;
        }
    }
    Ok((delta, random_shares, shared_two_by_two, multi_shared_rand))
}

#[instrument(level=Level::DEBUG, skip_all, err)]
fn init_and_shares(
    ctx: &Context<impl Channel>,
    random_shares: &mut FileOrMemBuf<Share>,
) -> Result<FileOrMemBuf<(Share, Share)>, Error> {
    let &Context {
        circ, num_and_ops, ..
    } = ctx;
    if num_and_ops == 0 {
        return Ok(FileOrMemBuf::new(None, 0)?);
    }
    let mut random_shares_iter = random_shares.iter()?;
    let mut shares = vec![Share(false, Auth(vec![])); circ.max_reg_count];

    let mut and_shares = FileOrMemBuf::new(ctx.tmp_dir, num_and_ops)?;
    // It is important that we use the and_share_batch_size as the max_chunk_size here, because we will directly
    // read the chunks in the gen_auth_bits method.
    let max_chunk_size = ctx.and_share_batch_size();
    let mut chunk = Vec::with_capacity(max_chunk_size);
    for (w, inst) in circ.insts.iter().enumerate() {
        match inst.op {
            Op::Input(_) | Op::And(_) => {
                let share = random_shares_iter
                    .next()
                    .ok_or(MpcError::MissingPreprocessingShareForInst(w))??;
                if let Op::And(And(x, y)) = inst.op {
                    chunk.push((shares[x].clone(), shares[y].clone()));
                }
                shares[inst.out] = share.clone();
            }
            Op::Not(Not(x)) => {
                shares[inst.out] = shares[x].clone();
            }
            Op::Xor(Xor(x, y)) => {
                shares[inst.out] = &shares[x] ^ &shares[y];
            }
        }
        if chunk.len() >= max_chunk_size {
            and_shares.write_chunk(&chunk)?;
            chunk.clear();
        }
    }
    if !chunk.is_empty() {
        and_shares.write_chunk(&chunk)?;
    }
    Ok(and_shares)
}

#[instrument(level=Level::DEBUG, skip_all, err)]
async fn gen_auth_bits(
    ctx: &Context<'_, '_, '_, '_, '_, impl Channel>,
    delta: Delta,
    mut and_shares: FileOrMemBuf<(Share, Share)>,
    mut shared_two_by_two: Option<Vec<Vec<Option<ChaCha20Rng>>>>,
    mut multi_shared_rand: Option<ChaCha20Rng>,
) -> Result<FileOrMemBuf<Share>, Error> {
    let &Context {
        channel,
        p_fpre,
        p_own,
        p_max,
        num_and_ops,
        ..
    } = ctx;
    if num_and_ops == 0 {
        return Ok(FileOrMemBuf::new(None, 0)?);
    }
    let mut auth_bits = FileOrMemBuf::new(ctx.tmp_dir, num_and_ops)?;
    if let Preprocessor::TrustedDealer(p_fpre) = p_fpre {
        let and_shares: Vec<_> = and_shares.iter()?.collect::<Result<_, _>>()?;
        (_, auth_bits) = try_join(send_to(channel, p_fpre, "AND shares", &and_shares), async {
            Ok(FileOrMemBuf::Memory {
                data: recv_vec_from(channel, p_fpre, "AND shares", num_and_ops).await?,
            })
        })
        .await?;
    } else {
        let batch_size = ctx.and_share_batch_size();
        let shared_two_by_two = shared_two_by_two
            .as_mut()
            .expect("Set in fn_independent_pre");
        let multi_shared_rand = multi_shared_rand
            .as_mut()
            .expect("Set in fn_independent_pre");
        for and_shares in and_shares.chunks(batch_size)? {
            let and_shares = and_shares?;
            debug!(size = and_shares.len(), "Generating auth bits batch");

            // TODO choose batch_size to minimize bucket_size?
            let b = bucket_size(and_shares.len());
            let xyz_shares = fashare(
                (channel, delta),
                p_own,
                p_max,
                // * 3 because we turn these into beaver triples
                and_shares.len() * b * 3,
                shared_two_by_two,
                multi_shared_rand,
            )
            .await?;
            let batch_auth_bits = beaver_aand(
                (channel, delta),
                &and_shares,
                p_own,
                p_max,
                and_shares.len(),
                multi_shared_rand,
                &xyz_shares,
            )
            .await?;
            auth_bits.write_chunk(&batch_auth_bits)?;
        }
    }
    Ok(auth_bits)
}

// TODO Consider optimizing type complexity of Result here
#[allow(clippy::type_complexity)]
#[instrument(level=Level::DEBUG, skip_all, err)]
async fn garble(
    ctx: &Context<'_, '_, '_, '_, '_, impl Channel>,
    delta: Delta,
    mut auth_bits: FileOrMemBuf<Share>,
    random_shares: &mut FileOrMemBuf<Share>,
) -> Result<
    (
        FileOrMemBuf<[Share; 4]>,
        Vec<FileOrMemBuf<GarbledGate>>,
        Vec<Share>,
        Vec<Label>,
        Vec<Label>,
    ),
    Error,
> {
    let &Context {
        channel,
        circ,
        is_contrib,
        p_eval,
        p_max,
        num_and_ops,
        tmp_dir,
        ..
    } = ctx;
    let mut random_shares = random_shares.iter()?;
    let mut shares = vec![Share(false, Auth(vec![])); circ.max_reg_count];
    let mut labels = vec![Label(Block::ZERO); circ.max_reg_count];
    let mut input_labels = vec![];
    let mut auth_bits = auth_bits.iter()?;
    let mut table_shares = FileOrMemBuf::default();
    let mut files = vec![];
    let max_garbled_gates_per_chunk = ctx.and_share_batch_size();

    if is_contrib {
        debug!("Contributing party to garbled circuit");
        let mut preprocessed_gates = vec![];
        for (w, inst) in circ.insts.iter().enumerate() {
            match inst.op {
                Op::And(And(x, y)) => {
                    let Share(r_x, mac_r_x_key_s_x) = shares[x].clone();
                    let Share(r_y, mac_r_y_key_s_y) = shares[y].clone();
                    let rand_share = random_shares
                        .next()
                        .ok_or(MpcError::MissingPreprocessingShareForInst(w))??;
                    let Share(r_gamma, mac_r_gamma_key_s_gamma) = rand_share.clone();
                    let Share(r_sig, mac_r_sig_key_s_sig) = auth_bits
                        .next()
                        .ok_or(MpcError::MissingAndShareForInst(w))??;
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

                    let label_x_0 = labels[x];
                    let label_y_0 = labels[y];
                    let label_x_1 = label_x_0 ^ delta;
                    let label_y_1 = label_y_0 ^ delta;

                    let k0 = GarblingKey::new(label_x_0, label_y_0, w, 0);
                    let k1 = GarblingKey::new(label_x_0, label_y_1, w, 1);
                    let k2 = GarblingKey::new(label_x_1, label_y_0, w, 2);
                    let k3 = GarblingKey::new(label_x_1, label_y_1, w, 3);

                    let label_gamma_0 = Label(random());
                    let row0_label = label_gamma_0 ^ row0.xor_keys() ^ (row0.bit() & delta);
                    let row1_label = label_gamma_0 ^ row1.xor_keys() ^ (row1.bit() & delta);
                    let row2_label = label_gamma_0 ^ row2.xor_keys() ^ (row2.bit() & delta);
                    let row3_label = label_gamma_0 ^ row3.xor_keys() ^ (row3.bit() & delta);

                    let garbled0 = encrypt(&k0, (row0.bit(), row0.macs(), row0_label))?;
                    let garbled1 = encrypt(&k1, (row1.bit(), row1.macs(), row1_label))?;
                    let garbled2 = encrypt(&k2, (row2.bit(), row2.macs(), row2_label))?;
                    let garbled3 = encrypt(&k3, (row3.bit(), row3.macs(), row3_label))?;

                    preprocessed_gates.push(GarbledGate([garbled0, garbled1, garbled2, garbled3]));
                    shares[inst.out] = rand_share;
                    labels[inst.out] = label_gamma_0;
                    if preprocessed_gates.len() >= max_garbled_gates_per_chunk {
                        send_to(channel, p_eval, "preprocessed gates", &preprocessed_gates).await?;
                        preprocessed_gates.clear();
                    }
                }
                Op::Xor(Xor(x, y)) => {
                    shares[inst.out] = &shares[x] ^ &shares[y];
                    labels[inst.out] = labels[x] ^ labels[y];
                }
                Op::Not(Not(x)) => {
                    shares[inst.out] = shares[x].clone();
                    labels[inst.out] = labels[x] ^ delta;
                }
                Op::Input(_) => {
                    let label = Label(random());
                    labels[inst.out] = label;
                    input_labels.push(label);
                    shares[inst.out] = random_shares
                        .next()
                        .ok_or(MpcError::MissingPreprocessingShareForInst(w))??;
                }
            }
        }
        if !preprocessed_gates.is_empty() {
            send_to(channel, p_eval, "preprocessed gates", &preprocessed_gates).await?;
        }
    } else {
        debug!("Evaluator party, receiving preprocessed gates");
        files = try_join_all((0..p_max).map(async |p| {
            let mut f = FileOrMemBuf::new(ctx.tmp_dir, num_and_ops)?;
            if p != p_eval {
                for chunk_size in chunk_size_iter(num_and_ops, max_garbled_gates_per_chunk) {
                    let gates =
                        recv_vec_from::<GarbledGate>(channel, p, "preprocessed gates", chunk_size)
                            .await?;
                    f.write_chunk(&gates)?;
                }
                Ok::<_, Error>(f)
            } else {
                Ok(f)
            }
        }))
        .await?;
        table_shares = FileOrMemBuf::new(tmp_dir, num_and_ops)?;
        let max_chunk_size = ctx.and_share_batch_size();
        let mut table_shares_chunk = Vec::with_capacity(max_chunk_size);
        for (w, inst) in circ.insts.iter().enumerate() {
            match inst.op {
                Op::And(And(x, y)) => {
                    let x = shares[x].clone();
                    let y = shares[y].clone();
                    let rand_share = random_shares
                        .next()
                        .ok_or(MpcError::MissingPreprocessingShareForInst(w))??;
                    let gamma = rand_share.clone();
                    let Share(s_x, mac_s_x_key_r_x) = x;
                    let Share(s_y, mac_s_y_key_r_y) = y;
                    let Share(s_gamma, mac_s_gamma_key_r_gamma) = gamma;
                    let sigma = auth_bits
                        .next()
                        .ok_or(MpcError::MissingAndShareForInst(w))??;
                    let Share(s_sig, mac_s_sig_key_r_sig) = sigma;
                    let s = s_sig ^ s_gamma;
                    let mac_s_key_r_0 = &mac_s_sig_key_r_sig ^ &mac_s_gamma_key_r_gamma;
                    let mac_s_key_r_1 = &mac_s_key_r_0 ^ &mac_s_x_key_r_x;
                    let row0 = Share(s, mac_s_key_r_0.clone());
                    let row1 = Share(s ^ s_x, mac_s_key_r_1.clone());
                    let row2 = Share(s ^ s_y, &mac_s_key_r_0 ^ &mac_s_y_key_r_y);
                    let row3 = Share(s ^ s_x ^ s_y ^ true, &mac_s_key_r_1 ^ &mac_s_y_key_r_y);
                    table_shares_chunk.push([row0, row1, row2, row3]);
                    if table_shares_chunk.len() >= max_chunk_size {
                        table_shares.write_chunk(&table_shares_chunk)?;
                        table_shares_chunk.clear();
                    }
                    shares[inst.out] = rand_share;
                }
                Op::Xor(Xor(x, y)) => {
                    shares[inst.out] = &shares[x] ^ &shares[y];
                }
                Op::Not(Not(x)) => {
                    shares[inst.out] = shares[x].clone();
                }
                Op::Input(_) => {
                    shares[inst.out] = random_shares
                        .next()
                        .ok_or(MpcError::MissingPreprocessingShareForInst(w))??;
                }
            }
        }
        if !table_shares_chunk.is_empty() {
            table_shares.write_chunk(&table_shares_chunk)?;
        }
    }
    Ok((table_shares, files, shares, labels, input_labels))
}

// TODO Consider optimizing type complexity of Result here
#[allow(clippy::type_complexity)]
#[instrument(level=Level::DEBUG, skip_all, fields(
    num_inputs = ctx.num_inputs,
), err)]
async fn input_processing(
    ctx: &Context<'_, '_, '_, '_, '_, impl Channel>,
    delta: Delta,
    input_labels: &[Label],
    random_shares: &mut FileOrMemBuf<Share>,
) -> Result<(Vec<Option<bool>>, Vec<Option<Vec<Label>>>), Error> {
    let &Context {
        channel,
        circ,
        inputs,
        is_contrib,
        p_eval,
        p_own,
        p_max,
        num_inputs,
        ..
    } = ctx;
    let random_input_shares: Vec<_> = random_shares
        .iter()?
        .take(num_inputs)
        .collect::<Result<_, _>>()?;
    let mut wire_shares_for_others = vec![vec![None; circ.max_reg_count]; p_max];
    for (w, inst) in circ.insts.iter().enumerate() {
        if let Op::Input(input @ Input { party, .. }) = inst.op {
            let Share(bit, Auth(macs_and_keys)) = random_input_shares[w].clone();
            let Some((mac, _)) = macs_and_keys.get(party as usize) else {
                return Err(MpcError::MissingSharesForInput(input).into());
            };

            if party as usize != p_own {
                wire_shares_for_others[party as usize][inst.out] = Some((bit, *mac));
            }
        }
    }
    let wire_shares_from_others =
        scatter(channel, p_own, "wire shares", &wire_shares_for_others).await?;

    let mut masked_inputs = vec![None; circ.max_reg_count];
    for (w, inst) in circ.insts.iter().enumerate() {
        if let Op::Input(Input { party, input }) = inst.op
            && p_own == party as usize
        {
            let Some(input) = inputs.get(input as usize) else {
                return Err(MpcError::InstWithoutInput(w).into());
            };
            let Share(own_share, Auth(own_macs_and_keys)) = random_input_shares[w].clone();
            let mut masked_input = *input ^ own_share;
            for p in 0..p_max {
                if let Some((_, key)) = own_macs_and_keys.get(p).copied()
                    && p != p_own
                {
                    let Some(other_shares) = wire_shares_from_others.get(p) else {
                        return Err(MpcError::InvalidInputMacForInst(w).into());
                    };
                    let Some((other_share, mac)) =
                        other_shares.get(inst.out.0 as usize).copied().flatten()
                    else {
                        return Err(MpcError::InvalidInputMacForInst(w).into());
                    };
                    if mac != key ^ (other_share & delta) {
                        return Err(MpcError::InvalidInputMacForInst(w).into());
                    } else {
                        masked_input ^= other_share;
                    }
                }
            }
            masked_inputs[inst.out] = Some(masked_input)
        }
    }
    let masked_inputs_from_other_party =
        broadcast(channel, p_own, p_max, "masked inputs", &masked_inputs).await?;
    for p in (0..p_max).filter(|p| *p != p_own) {
        for (w, (mask_other, masked_input)) in masked_inputs_from_other_party[p]
            .iter()
            .zip(masked_inputs.iter_mut())
            .enumerate()
        {
            if let Some(mask_other) = mask_other {
                if masked_input.is_some() {
                    return Err(MpcError::ConflictingInputMask(w).into());
                }
                *masked_input = Some(*mask_other);
            }
        }
    }
    let other_input_labels = Mutex::new(vec![None; circ.max_reg_count]);
    if is_contrib {
        debug!("Contributing party, sending masked inputs and labels");
        let labels_of_other_inputs: Vec<Option<Label>> = masked_inputs
            .iter()
            .enumerate()
            .map(|(w, input)| input.map(|b| input_labels[w] ^ (b & delta)))
            .collect();
        send_to(channel, p_eval, "labels", &labels_of_other_inputs).await?;
    } else {
        debug!("Evaluator party, receiving masked inputs and labels");
        try_join_all((0..p_max).filter(|p| *p != p_own).map(async |p| {
            let labels_of_own_inputs =
                recv_vec_from::<Option<Label>>(channel, p, "labels", circ.max_reg_count).await?;
            let mut input_labels = other_input_labels.lock().expect("poison");
            for (w, label) in labels_of_own_inputs.iter().enumerate() {
                if let Some(label) = label {
                    let labels = input_labels[w].get_or_insert(vec![Label(Block::ZERO); p_max]);
                    labels[p] = *label;
                }
            }
            Ok::<_, channel::Error>(())
        }))
        .await?;
    }
    let input_labels = other_input_labels.into_inner().expect("poison");
    Ok((masked_inputs, input_labels))
}

#[instrument(level=Level::DEBUG, skip_all, fields(
    num_garble_files= garble_files.len(),
    num_masked_inputs = masked_inputs.len(),
    num_input_labels = input_labels.len(),
), err)]
fn evaluate(
    ctx: &Context<impl Channel>,
    delta: Delta,
    mut table_shares: FileOrMemBuf<[Share; 4]>,
    mut garble_files: Vec<FileOrMemBuf<GarbledGate>>,
    masked_inputs: Vec<Option<bool>>,
    input_labels: Vec<Option<Vec<Label>>>,
) -> Result<(Vec<bool>, Vec<Vec<Label>>), Error> {
    let &Context {
        circ,
        is_contrib,
        p_own,
        p_eval,
        p_max,
        ..
    } = ctx;
    let mut values: Vec<bool> = vec![false; circ.max_reg_count];
    let mut labels_eval: Vec<Vec<Label>> = vec![vec![]; circ.max_reg_count];
    let mut garbled_gates: Vec<_> = garble_files
        .iter_mut()
        .map(|file| file.iter())
        .collect::<std::io::Result<_>>()?;

    let mut table_shares = table_shares.iter()?;
    if !is_contrib {
        debug!("Evaluator party, performing circuit evaluation");
        for (w, inst) in circ.insts.iter().enumerate() {
            let (value, label) = match inst.op {
                Op::Input(_) => {
                    let input = masked_inputs
                        .get(inst.out.0 as usize)
                        .copied()
                        .flatten()
                        .ok_or(MpcError::InputWithoutValue(inst.out.0 as usize))?;
                    let label = input_labels
                        .get(inst.out.0 as usize)
                        .cloned()
                        .flatten()
                        .ok_or(MpcError::InputWithoutLabel(inst.out.0 as usize))?;
                    (input, label.clone())
                }
                Op::Not(Not(x)) => {
                    let input = values[x];
                    let label = &labels_eval[x];
                    (!input, label.clone())
                }
                Op::Xor(Xor(x, y)) => {
                    let input_x = values[x];
                    let label_x = &labels_eval[x];
                    let input_y = values[y];
                    let label_y = &labels_eval[y];
                    (input_x ^ input_y, xor_labels(label_x, label_y))
                }
                Op::And(And(x, y)) => {
                    let input_x = values[x];
                    let label_x = &labels_eval[x];
                    let input_y = values[y];
                    let label_y = &labels_eval[y];
                    let i = 2 * (input_x as usize) + (input_y as usize);
                    let table_shares = table_shares
                        .next()
                        .ok_or(MpcError::MissingTableShareForInst(w))??;

                    let mut label = vec![Label(Block::ZERO); p_max];
                    let mut macs = vec![vec![]; p_max];
                    let Share(mut s, mac_s_key_r) = table_shares[i].clone();
                    macs[p_eval] = mac_s_key_r.macs();
                    let Auth(mac_s_key_r) = mac_s_key_r;
                    for (p, mac_s_key_r) in mac_s_key_r.iter().enumerate() {
                        let (_, key_r) = mac_s_key_r;
                        if p == p_own {
                            continue;
                        }
                        let GarbledGate(garbled_gate) = garbled_gates[p]
                            .next()
                            .ok_or(MpcError::MissingGarbledGate(w))??;
                        let garbling_key = GarblingKey::new(label_x[p], label_y[p], w, i as u8);
                        let garbled_row = garbled_gate[i].clone();
                        let (r, mac_r, label_share) =
                            decrypt(&garbling_key, &garbled_row).expect("decryption failed");
                        let Some(mac_r_for_eval) = mac_r.get(p_eval).copied() else {
                            return Err(MpcError::InvalidInputMacForInst(w).into());
                        };
                        if mac_r_for_eval != *key_r ^ (r & delta) {
                            return Err(MpcError::InvalidInputMacForInst(w).into());
                        }
                        s ^= r;
                        label[p] = label_share;
                        macs[p] = mac_r;
                    }
                    for p_i in (0..p_max).filter(|p_i| *p_i != p_eval) {
                        for p_j in (0..p_max).filter(|p_j| *p_j != p_i) {
                            if let Some(macs) = macs.get(p_j)
                                && let Some(mac) = macs.get(p_i).copied()
                            {
                                label[p_i] = label[p_i] ^ mac
                            }
                        }
                    }
                    (s, label)
                }
            };
            values[inst.out] = value;
            labels_eval[inst.out] = label;
        }
    }
    Ok((values, labels_eval))
}

#[instrument(level=Level::DEBUG, skip_all, fields(
    num_output_wires = ctx.circ.output_regs.len(),
), err)]
async fn output(
    ctx: &Context<'_, '_, '_, '_, '_, impl Channel>,
    delta: Delta,
    shares: Vec<Share>,
    labels: Vec<Label>,
    values: Vec<bool>,
    labels_eval: Vec<Vec<Label>>,
) -> Result<Vec<bool>, Error> {
    let &Context {
        channel,
        circ,
        is_contrib,
        p_eval,
        p_own,
        p_max,
        p_out,
        ..
    } = ctx;

    // We need to exchange shares and macs for each output register. However, in circ.output_regs
    // the same register might be present multiple times if the output should contain the same bit
    // multiple times. For efficiency and correctness, we operate on the set of unique registers
    // in most cases. Only in the very end of this method, when actually collecting the result bits
    // we use `circ.output_regs` including the potentially duplicate registers.
    let unqiue_output_regs: BTreeSet<_> = circ.output_regs.iter().copied().collect();

    try_join_all(
        p_out
            .iter()
            .copied()
            .filter(|p| *p != p_own)
            .map(async |p_out| {
                // TODO rework this to not allocate max_reg_count but only output size
                //  see https://github.com/sine-fdn/polytune/issues/113
                let mut outputs = vec![None; circ.max_reg_count];
                for &out in &unqiue_output_regs {
                    let Share(bit, Auth(macs_and_keys)) = shares[out].clone();
                    if let Some((mac, _)) = macs_and_keys.get(p_out).copied() {
                        outputs[out] = Some((bit, mac));
                    }
                }
                send_to(channel, p_out, "output wire shares", &outputs).await
            }),
    )
    .await?;
    let mut output_wire_shares: Vec<Vec<Option<(bool, Mac)>>> = vec![];
    if p_out.contains(&p_own) {
        output_wire_shares = try_join_all((0..p_max).map(async |p| {
            if p != p_own {
                recv_vec_from(channel, p, "output wire shares", circ.max_reg_count).await
            } else {
                Ok::<_, channel::Error>(vec![])
            }
        }))
        .await?;
    }
    let mut input_regs = vec![None; circ.max_reg_count];
    if !is_contrib {
        try_join_all(
            p_out
                .iter()
                .copied()
                .filter(|p| *p != p_own)
                .map(async |p_out| {
                    // TODO rework this to not allocate max_reg_count but only output size
                    //  see https://github.com/sine-fdn/polytune/issues/113
                    let mut wires_and_labels = vec![None; circ.max_reg_count];
                    for &out in &unqiue_output_regs {
                        wires_and_labels[out] = Some((values[out], labels_eval[out][p_out]));
                    }
                    send_to(channel, p_out, "lambda", &wires_and_labels).await
                }),
        )
        .await?;
        for &out in &unqiue_output_regs {
            input_regs[out] = Some(values[out]);
        }
    } else if p_out.contains(&p_own) {
        let wires_and_labels =
            recv_vec_from::<Option<(bool, Label)>>(channel, p_eval, "lambda", circ.max_reg_count)
                .await?;
        for &out in &unqiue_output_regs {
            if !(wires_and_labels[out] == Some((true, labels[out] ^ delta))
                || wires_and_labels[out] == Some((false, labels[out])))
            {
                return Err(MpcError::InvalidOutputLabel(out).into());
            }
            input_regs[out] = wires_and_labels[out].map(|(bit, _)| bit);
        }
    }
    let mut outputs = vec![];
    if p_out.contains(&p_own) {
        let mut output_wires = vec![None; circ.max_reg_count];
        for &out in &unqiue_output_regs {
            let Some(input) = input_regs.get(out.0 as usize).copied().flatten() else {
                return Err(MpcError::MissingOutputShareForOutReg(out).into());
            };
            let Share(bit, _) = &shares[out];
            output_wires[out] = Some(input ^ bit);
        }
        for p in (0..p_max).filter(|p| *p != p_own) {
            // It is crucial for correctness that here we iterate over the unique registers,
            // as otherwise we XOR output_wires[out] a wrong number of times for duplicate registers.
            for &out in &unqiue_output_regs {
                let output_wire = &output_wire_shares[p][out];
                let Share(_, Auth(mac_s_key_r)) = &shares[out];
                let Some((_, key_r)) = mac_s_key_r.get(p).copied() else {
                    return Err(MpcError::InvalidOutputMac(out).into());
                };
                if let Some((r, mac_r)) = output_wire {
                    if *mac_r != key_r ^ (*r & delta) {
                        return Err(MpcError::InvalidOutputMac(out).into());
                    } else if let Some(o) = output_wires.get(out.0 as usize).copied().flatten() {
                        output_wires[out] = Some(o ^ r);
                    };
                }
            }
        }
        // Here, we explicitly don't use unique_output_regs, as duplicate output registers
        // must also result in duplicate output bits
        for out in circ.output_regs.iter() {
            if let Some(o) = output_wires.get(out.0 as usize).copied().flatten() {
                outputs.push(o);
            }
        }
    }
    Ok(outputs)
}

fn chunk_size_iter(total: usize, chunk_size: usize) -> Box<dyn Iterator<Item = usize> + Send> {
    if chunk_size == 0 {
        return Box::new(iter::empty());
    }
    let remainder = total % chunk_size;
    let iter = iter::repeat_n(chunk_size, total / chunk_size);
    if remainder != 0 {
        Box::new(iter.chain(Some(remainder)))
    } else {
        Box::new(iter)
    }
}
