use maybe_async::sync_impl;
use polytune::{
    fpre::{fpre, Error as FpreError},
    garble_lang::circuit::Circuit,
    protocol::{mpc, Error as MpcError, Preprocessor},
};
use sync_channel::SimpleSyncChannel;

mod sync_channel;

/// A custom error type for MPC computation and communication.
#[derive(Debug)]
pub enum Error {
    /// Caused by the core MPC protocol computation.
    MpcError(MpcError),
    /// Caused by the preprocessing phase.
    FpreError(FpreError),
    /// Caused by thread-related errors.
    ThreadError(String),
}

/// Simulates the multi party computation with the given inputs and party 0 as the evaluator.
#[sync_impl]
pub fn simulate_mpc_sync(
    circuit: &Circuit,
    inputs: &[&[bool]],
    output_parties: &[usize],
    trusted: bool,
) -> Result<Vec<bool>, Error> {
    let p_eval = 0;
    let p_pre = inputs.len();

    let mut channels: Vec<SimpleSyncChannel>;
    let fpre_thread = if trusted {
        channels = SimpleSyncChannel::channels(inputs.len() + 1);
        let mut channel = channels.pop().unwrap();
        let parties = inputs.len();
        Some(std::thread::spawn(move || {
            fpre(&mut channel, parties).map_err(Error::FpreError)
        }))
    } else {
        channels = SimpleSyncChannel::channels(inputs.len());
        None
    };

    let mut parties = channels.into_iter().zip(inputs).enumerate();
    let Some(evaluator) = parties.next() else {
        return Ok(vec![]);
    };
    let p_fpre = if trusted {
        Preprocessor::TrustedDealer(p_pre)
    } else {
        Preprocessor::Untrusted
    };

    let mut computation_threads = vec![];
    for (p_own, (mut channel, inputs)) in parties {
        let circuit = circuit.clone();
        let inputs = inputs.to_vec();
        let output_parties = output_parties.to_vec();
        let handle = std::thread::spawn(move || {
            let result = mpc(
                &mut channel,
                &circuit,
                &inputs,
                p_fpre,
                p_eval,
                p_own,
                &output_parties,
            );
            match result {
                Err(e) => Err(Error::MpcError(e)),
                Ok(res) => Ok(res),
            }
        });
        computation_threads.push(handle);
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
    );

    match eval_result {
        Err(e) => Err(Error::MpcError(e)),
        Ok(res) => {
            let mut outputs = vec![res];
            for handle in computation_threads {
                match handle.join() {
                    Ok(Ok(output)) if !output.is_empty() => outputs.push(output),
                    Ok(Err(e)) => return Err(e),
                    Err(e) => return Err(Error::ThreadError(format!("Thread panicked: {:?}", e))),
                    _ => {}
                }
            }
            if let Some(handle) = fpre_thread {
                match handle.join() {
                    Ok(Err(e)) => return Err(e),
                    Err(e) => {
                        return Err(Error::ThreadError(format!("fpre thread panicked: {:?}", e)))
                    }
                    _ => {}
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
