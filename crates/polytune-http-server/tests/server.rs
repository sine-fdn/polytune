//! Tests of polytune-http-server.
use std::{
    collections::HashMap, env::current_dir, fs, net::SocketAddr, path::PathBuf, time::Duration,
};

use jsonwebtoken::EncodingKey;
use polytune_http_server::{JwtConf, ServerOpts};
use polytune_server_core::Policy;
use rand::seq::SliceRandom;
use tokio::{sync::mpsc, task::JoinSet};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};
use url::Url;

use crate::common::{
    output_server::{self, MpcResult},
    random_policy, start_servers, test_rng,
};

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_eval() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .try_init();

    const POLICIES_SCHEDULED: usize = 50;

    let addrs = [
        "127.0.0.1:8013".parse().expect("parsing participants addr"),
        "127.0.0.1:8014".parse().expect("parsing participants addr"),
    ];
    let output_addr: SocketAddr = "127.0.0.1:8099".parse().expect("parsing output addr");
    let output_url: Url = format!("http://{output_addr}/output/")
        .parse()
        .expect("parsing output url");
    let jwt_key = fs::read(
        env!("CARGO_MANIFEST_DIR")
            .parse::<PathBuf>()
            .expect("crate dir")
            .join("test_key/test-private.pem"),
    )
    .expect("reading test private ky");
    let key =
        EncodingKey::from_ec_pem(&jwt_key).expect("JWT key is not a valid ECDSA PEM PKCS#8 key");
    start_servers(
        addrs,
        ServerOpts {
            concurrency: 3,
            tmp_dir: Some(current_dir().expect("current dir")),
            jwt_conf: Some(JwtConf {
                key,
                claims: Some(
                    serde_json::json!({"roles":["TEST_ROLE"]})
                        .as_object()
                        .expect("json is object")
                        .clone(),
                ),
                iss: "polytune".to_string(),
                exp: 300,
            }),
            cancel: None,
        },
    )
    .await;
    let (out_sender, mut out_receiver) = mpsc::channel(10);
    tokio::spawn(output_server::server(output_addr, out_sender));

    let client = reqwest::Client::new();

    let mut expected = HashMap::new();
    let mut policies: Vec<Policy> = (0..POLICIES_SCHEDULED)
        .flat_map(|_| {
            let (policies, lit) = random_policy(addrs, output_url.clone());
            expected.insert(policies[0].computation_id, MpcResult::Success(lit));
            policies
        })
        .collect();
    {
        let mut rng = test_rng();
        policies.shuffle(&mut *rng);
    }

    let mut js = JoinSet::new();
    for policy in policies {
        js.spawn(
            client
                .post(
                    policy.participants[policy.party]
                        .join("schedule")
                        .expect("schedule URL error"),
                )
                .json(&policy)
                .send(),
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    for res in js.join_all().await {
        res.expect("schedule error")
            .error_for_status()
            .expect("schedule error");
    }
    info!("scheduled all policies");

    for _ in 0..POLICIES_SCHEDULED {
        let (id, res) = out_receiver.recv().await.expect("output sender dropped");
        assert_eq!(expected[&id], res)
    }
}
