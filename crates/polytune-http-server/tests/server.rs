//! Tests of polytune-http-server.
use std::{collections::HashMap, env::current_dir, fs, path::PathBuf, time::Duration};

use jsonwebtoken::EncodingKey;
use polytune_http_server::{JwtConf, ServerOpts};
use polytune_server_core::Policy;
use rand::seq::SliceRandom;
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::info;
use uuid::Uuid;

use crate::common::{
    init_tracing,
    output_server::{self, MpcResult},
    random_policy, start_servers, test_rng,
};

mod common;

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_eval() {
    init_tracing();

    const POLICIES_SCHEDULED: usize = 50;
    let jwt_key = fs::read(
        env!("CARGO_MANIFEST_DIR")
            .parse::<PathBuf>()
            .expect("crate dir")
            .join("test_key/test-private.pem"),
    )
    .expect("reading test private ky");
    let key =
        EncodingKey::from_ec_pem(&jwt_key).expect("JWT key is not a valid ECDSA PEM PKCS#8 key");
    let participants = start_servers(ServerOpts {
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
            exp: 1,
        }),
        cancel: None,
    })
    .await;
    let (out_sender, mut out_receiver) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let (output_url, output_server_fut) = output_server::server(out_sender, None).await;
    tokio::spawn(
        cancel_token
            .clone()
            .run_until_cancelled_owned(output_server_fut),
    );
    let _g = cancel_token.drop_guard();
    let client = reqwest::Client::new();

    let mut expected = HashMap::new();
    let mut policies: Vec<Policy> = (0..POLICIES_SCHEDULED)
        .flat_map(|_| {
            let (policies, lit) = random_policy(participants.clone(), output_url.clone());
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

/// Test the evaluation of a policy with empty constants
#[tokio::test(flavor = "multi_thread")]
async fn policy_without_consts() {
    init_tracing();

    let participants = start_servers(ServerOpts {
        concurrency: 3,
        tmp_dir: Some(current_dir().expect("current dir")),
        jwt_conf: None,
        cancel: None,
    })
    .await;
    let (out_sender, mut out_receiver) = mpsc::channel(10);
    let cancel_token = CancellationToken::new();
    let (output_url, output_server_fut) = output_server::server(out_sender, None).await;
    tokio::spawn(
        cancel_token
            .clone()
            .run_until_cancelled_owned(output_server_fut),
    );
    let _g = cancel_token.drop_guard();

    let client = reqwest::Client::new();

    let computation_id = Uuid::new_v4();
    let output_url = output_url
        .join(&computation_id.to_string())
        .expect("parse URL");
    let policy0 = Policy {
        computation_id,
        participants,
        program: "pub fn main(x: u8, y: u8) -> u8 { x + y }".to_string(),
        leader: 0,
        party: 0,
        input: 2_u8.into(),
        output: Some(output_url),
        constants: HashMap::new(),
    };

    let mut policy1 = policy0.clone();
    policy1.party = 1;
    let schedule_futs = [policy0, policy1].map(|p| {
        client
            .post(
                p.participants[p.party]
                    .join("schedule")
                    .expect("schedule URL error"),
            )
            .json(&p)
            .send()
    });
    let res = futures::future::try_join_all(schedule_futs)
        .await
        .expect("join failed");
    for res in res {
        res.error_for_status().expect("schedule failed");
    }

    for _ in 0..2 {
        let (_, res) = out_receiver.recv().await.expect("output sender dropped");
        assert_eq!(MpcResult::Success(4_u8.into()), res)
    }
}
