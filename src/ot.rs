//! Ferret OT implementation from the MPZ framework

use futures::TryFutureExt as _;
use serio::channel::{duplex, MemoryDuplex};

use mpz_common::executor::{test_st_executor, STExecutor};
use mpz_core::{lpn::LpnParameters, Block};
use mpz_ot::{
    ferret::{FerretConfig, Receiver, Sender},
    ideal::cot::{ideal_rcot, IdealCOTReceiver, IdealCOTSender},
    Correlation, OTError, RCOTReceiverOutput, RCOTSenderOutput, RandomCOTReceiver, RandomCOTSender,
    TransferId,
};
use mpz_ot_core::ferret::LpnType;

// l = n - k = 8380
const LPN_PARAMETERS_TEST: LpnParameters = LpnParameters {
    n: 9600,
    k: 1220,
    t: 600,
};

/// Transform Block to u128
pub fn block_to_u128(inp: Block) -> u128 {
    u128::from_le_bytes(inp.to_bytes())
}

/// Transform u128 to Block
pub fn u128_to_block(inp: u128) -> Block {
    Block::new(inp.to_le_bytes())
}

pub(crate) async fn mpz_ot_sender(
    count: usize,
    ctx_sender: &mut STExecutor<MemoryDuplex>,
    rcot_sender: IdealCOTSender,
) -> Result<(TransferId, Vec<Block>, u128), OTError> {
    let lpn_type: LpnType = LpnType::Regular;

    let config = FerretConfig::new(LPN_PARAMETERS_TEST, lpn_type);

    let mut sender = Sender::new(config, rcot_sender);

    sender
        .setup(ctx_sender)
        .map_err(OTError::from)
        .await
        .unwrap();

    // extend once.
    let num = LPN_PARAMETERS_TEST.k;
    sender
        .extend(ctx_sender, num)
        .map_err(OTError::from)
        .await
        .unwrap();

    // extend twice
    sender
        .extend(ctx_sender, count)
        .map_err(OTError::from)
        .await
        .unwrap();

    let RCOTSenderOutput {
        id: sender_id,
        msgs: u,
    } = sender
        .send_random_correlated(ctx_sender, count)
        .await
        .unwrap();

    Ok((sender_id, u, block_to_u128(sender.delta())))
}

pub(crate) async fn mpz_ot_receiver(
    count: usize,
    ctx_receiver: &mut STExecutor<MemoryDuplex>,
    rcot_receiver: IdealCOTReceiver,
) -> Result<(TransferId, Vec<bool>, Vec<Block>), OTError> {
    let lpn_type: LpnType = LpnType::Regular;

    let config = FerretConfig::new(LPN_PARAMETERS_TEST, lpn_type);

    let mut receiver = Receiver::new(config, rcot_receiver);

    receiver
        .setup(ctx_receiver)
        .map_err(OTError::from)
        .await
        .unwrap();

    // extend once.
    let num = LPN_PARAMETERS_TEST.k;
    receiver
        .extend(ctx_receiver, num)
        .map_err(OTError::from)
        .await
        .unwrap();

    // extend twice
    receiver
        .extend(ctx_receiver, count)
        .map_err(OTError::from)
        .await
        .unwrap();

    let RCOTReceiverOutput {
        id: receiver_id,
        choices: b,
        msgs: w,
    } = receiver
        .receive_random_correlated(ctx_receiver, count)
        .await
        .unwrap();

    Ok((receiver_id, b, w))
}

pub(crate) async fn _mpz_ot(count: usize) -> Result<bool, OTError> {
    let lpn_type: LpnType = LpnType::Regular;
    let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

    let (rcot_sender, rcot_receiver) = ideal_rcot();

    let config = FerretConfig::new(LPN_PARAMETERS_TEST, lpn_type);

    let mut sender = Sender::new(config.clone(), rcot_sender);
    let mut receiver = Receiver::new(config, rcot_receiver);

    tokio::try_join!(
        sender.setup(&mut ctx_sender).map_err(OTError::from),
        receiver.setup(&mut ctx_receiver).map_err(OTError::from)
    )
    .unwrap();

    // extend once.
    let num = LPN_PARAMETERS_TEST.k;
    tokio::try_join!(
        sender.extend(&mut ctx_sender, num).map_err(OTError::from),
        receiver
            .extend(&mut ctx_receiver, num)
            .map_err(OTError::from)
    )
    .unwrap();

    // extend twice
    tokio::try_join!(
        sender.extend(&mut ctx_sender, count).map_err(OTError::from),
        receiver
            .extend(&mut ctx_receiver, count)
            .map_err(OTError::from)
    )
    .unwrap();

    let (
        RCOTSenderOutput {
            id: _sender_id,
            msgs: _u,
        },
        RCOTReceiverOutput {
            id: _receiver_id,
            choices: _b,
            msgs: _w,
        },
    ) = tokio::try_join!(
        sender.send_random_correlated(&mut ctx_sender, count),
        receiver.receive_random_correlated(&mut ctx_receiver, count)
    )
    .unwrap();

    Ok(true)
}

pub(crate) async fn generate_ots(
    count: usize,
) -> Result<(u128, Vec<u128>, Vec<bool>, Vec<u128>), OTError> {
    let (io0, io1) = duplex(8);
    let mut ctx_receiver = STExecutor::new(io0);
    let mut ctx_sender = STExecutor::new(io1);

    let (rcot_sender, rcot_receiver) = ideal_rcot();

    let sender_task =
        tokio::spawn(async move { mpz_ot_sender(count, &mut ctx_sender, rcot_sender).await });

    let receiver_task =
        tokio::spawn(async move { mpz_ot_receiver(count, &mut ctx_receiver, rcot_receiver).await });

    // Await the results of both tasks
    let sender_result = sender_task.await;
    let receiver_result = receiver_task.await;

    // Handle errors from task execution
    let (_sender_id, u, delta) = match sender_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(e) => {
            eprintln!("Sender task join error: {:?}", e);
            return Ok((0, vec![], vec![], vec![]));
        }
    };

    let (_receiver_id, b, w) = match receiver_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            return Err(e);
        }
        Err(e) => {
            eprintln!("Receiver task join error: {:?}", e);
            return Ok((0, vec![], vec![], vec![]));
        }
    };

    let mut ublock: Vec<u128> = vec![0; u.len()];
    for i in 0..u.len() {
        ublock[i] = block_to_u128(u[i]);
    }
    let mut wblock: Vec<u128> = vec![0; w.len()];
    for i in 0..w.len() {
        wblock[i] = block_to_u128(w[i]);
    }

    /*for i in 0..count {
        println!("b     {:?}", b[i]);
        println!("u     {:?}", ublock[i]);
        println!("w     {:?}", wblock[i]);
    }*/

    Ok((delta, ublock, b, wblock))
}

#[cfg(test)]
mod tests {
    use futures::TryFutureExt as _;
    use rstest::*;
    use std::time::Instant;

    use mpz_common::executor::test_st_executor;
    use mpz_core::lpn::LpnParameters;
    use mpz_ot::{
        ferret::{FerretConfig, Receiver, Sender},
        ideal::cot::ideal_rcot,
        Correlation, OTError, RCOTReceiverOutput, RCOTSenderOutput, RandomCOTReceiver,
        RandomCOTSender,
    };
    use mpz_ot_core::{ferret::LpnType, test::assert_cot};

    // l = n - k = 8380
    const LPN_PARAMETERS_TEST: LpnParameters = LpnParameters {
        n: 9600,
        k: 1220,
        t: 600,
    };

    #[rstest]
    //#[case::uniform(LpnType::Uniform)]
    #[case::regular(LpnType::Regular)]
    #[tokio::test]
    async fn test_ferret(#[case] lpn_type: LpnType) {
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

        let (rcot_sender, rcot_receiver) = ideal_rcot();

        let config = FerretConfig::new(LPN_PARAMETERS_TEST, lpn_type);

        let mut sender = Sender::new(config.clone(), rcot_sender);
        let mut receiver = Receiver::new(config, rcot_receiver);

        tokio::try_join!(
            sender.setup(&mut ctx_sender).map_err(OTError::from),
            receiver.setup(&mut ctx_receiver).map_err(OTError::from)
        )
        .unwrap();

        let now = Instant::now();
        // extend once.
        let count = LPN_PARAMETERS_TEST.k;
        tokio::try_join!(
            sender.extend(&mut ctx_sender, count).map_err(OTError::from),
            receiver
                .extend(&mut ctx_receiver, count)
                .map_err(OTError::from)
        )
        .unwrap();

        // extend twice
        let count = 100;
        tokio::try_join!(
            sender.extend(&mut ctx_sender, count).map_err(OTError::from),
            receiver
                .extend(&mut ctx_receiver, count)
                .map_err(OTError::from)
        )
        .unwrap();

        let (
            RCOTSenderOutput {
                id: sender_id,
                msgs: u,
            },
            RCOTReceiverOutput {
                id: receiver_id,
                choices: b,
                msgs: w,
            },
        ) = tokio::try_join!(
            sender.send_random_correlated(&mut ctx_sender, count),
            receiver.receive_random_correlated(&mut ctx_receiver, count)
        )
        .unwrap();
        let elapsed = now.elapsed();
        println!("Elapsed: {:.2?}", elapsed);

        assert_eq!(sender_id, receiver_id);
        assert_cot(sender.delta(), &b, &u, &w);

        /*for i in 0..count {
            println!("d     {:?}", sender.delta());
            println!("b     {:?}", b[i]);
            println!("u     {:?}", block_to_u128(u[i]));
            println!("w     {:?}", block_to_u128(w[i]));
        }*/
    }
}
