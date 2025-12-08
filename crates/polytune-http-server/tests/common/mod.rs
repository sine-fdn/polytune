// The module is built separately for each integration test, so if some items
// are only used in one test but not the other, this will result in warnings
#![allow(dead_code)]

use std::{
    env,
    sync::{LazyLock, Mutex, MutexGuard},
    time::Duration,
};

use garble_lang::literal::Literal;
use polytune_http_server::{Server, ServerOpts};
use polytune_server_core::Policy;
use rand::{Rng, SeedableRng, rngs::StdRng};
use tracing::{Instrument, info, info_span};
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use url::Url;
use uuid::Uuid;

pub(crate) mod output_server;

static TEST_RNG: LazyLock<Mutex<StdRng>> = LazyLock::new(|| {
    let seed: u64 = if let Ok(var) = env::var("POLYTUNE_TEST_SEED") {
        var.parse().expect("POLYTUNE_TEST_SEED is invalid u64")
    } else {
        rand::random()
    };
    info!(seed, "testing seed");
    Mutex::new(StdRng::seed_from_u64(seed))
});

pub(crate) fn test_rng() -> MutexGuard<'static, StdRng> {
    TEST_RNG.lock().expect("TEST_RNG poisoned")
}

/// Start two local servers and return the URLs at which they are reachable.
pub(crate) async fn start_servers(opts: ServerOpts) -> Vec<Url> {
    let mut urls = vec![];

    for i in 0..2 {
        let mut server =
            Server::new_with_opts("127.0.0.1:0".parse().expect("addr parse"), opts.clone());
        let socket_addr = server.bind_socket().await.expect("bind");
        urls.push(Url::parse(&format!("http://{socket_addr}")).expect("url parse"));
        let span = info_span!("server", server = i);
        tokio::spawn(
            async move { server.start().await.expect("polytune server crashed") }.instrument(span),
        );
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    urls
}

const MEASLES_PROGRAM: &str = include_str!("../../garble_programs/measles.garble.rs");

pub(crate) fn random_policy(participants: Vec<Url>, output: Url) -> ([Policy; 2], Literal) {
    let computation_id = Uuid::new_v4();
    let mut rng = test_rng();
    let leader = rng.random_range(0..=1);
    let program = MEASLES_PROGRAM;

    let rows_0: usize = rng.random_range(0..=4);
    let rows_1: usize = rng.random_range(1..=20);
    let id_len: usize = rng.random_range(1..=8);
    let id_0: u8 = rng.random_range(0..=1);
    let policies = [0, 1].map(|party| {
        let input = if party == 0 {
            vec![vec![id_0; id_len]; rows_0].into()
        } else {
            vec![vec![1_u8; id_len]; rows_1].into()
        };
        let rows_const = if party == 0 {
            ("ROWS".to_string(), Literal::from(rows_0))
        } else {
            ("ROWS".to_string(), Literal::from(rows_1))
        };
        let constants = [rows_const, ("ID_LEN".to_string(), Literal::from(id_len))]
            .into_iter()
            .collect();

        let output = if party == leader {
            Some(
                output
                    .clone()
                    .join(&computation_id.to_string())
                    .expect("joining output url"),
            )
        } else {
            None
        };

        Policy {
            computation_id,
            participants: participants.clone(),
            program: program.to_string(),
            leader,
            party,
            input,
            output,
            constants,
        }
    });
    let expected = rows_0 > 0 && id_0 == 1;
    (policies, Literal::from(expected))
}

pub(crate) fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .try_init();
}
