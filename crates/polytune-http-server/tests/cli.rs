#![allow(clippy::unwrap_used)]
//! Integration tests.

#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    env, fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    thread::{self, sleep},
    time::Duration,
};

use garble_lang::literal::Literal;
use serde::Deserialize;
use tokio::sync::mpsc::channel;

use crate::output_server::MpcResult;

/// This test supports profiling with heaptrack or samply if installed by setting the corresponding
/// env variables. By setting the `POLYTUNE_TEST_BIG` variable, policies with a larger input
/// will be used.
#[test]
fn simulate() {
    let millis = 2000;
    println!("\n\n--- {millis}ms ---\n\n");
    let mut children = vec![];
    let use_big_input = env::var("POLYTUNE_TEST_BIG").is_ok();
    let heaptrack_profiling = env::var("POLYTUNE_TEST_HEAPTRACK").is_ok();
    let samply_profiling = env::var("POLYTUNE_TEST_SAMPLY").is_ok();
    let polytune_bin = PathBuf::from(env!("CARGO_BIN_EXE_polytune-http-server"));

    #[cfg(not(debug_assertions))]
    if samply_profiling || heaptrack_profiling {
        panic!("Use --profile=debug-release when profiling")
    }

    let cmd_prog = if heaptrack_profiling {
        "heaptrack".into()
    } else if samply_profiling {
        "samply".into()
    } else {
        polytune_bin.clone()
    };
    let mut common_args = if heaptrack_profiling {
        vec!["--record-only", polytune_bin.to_str().unwrap()]
    } else if samply_profiling {
        vec!["record", "--save-only", polytune_bin.to_str().unwrap()]
    } else {
        vec![]
    };

    if use_big_input {
        common_args.push("--tmp-dir=.");
    }
    if samply_profiling {
        fs::create_dir_all("output_p0").unwrap();
        fs::create_dir_all("output_p1").unwrap();
    }

    let mut cmd = Command::new(&cmd_prog);
    cmd.args(common_args.clone())
        .arg("--addr=127.0.0.1:8001")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if samply_profiling || heaptrack_profiling {
        cmd.current_dir("./output_p1");
    }
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().unwrap();

    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
    thread::spawn(move || {
        while let Some(Ok(line)) = stdout.next() {
            println!("party1> {line}");
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("party1> {line}");
        }
    });
    children.push(child);

    let mut cmd = Command::new(cmd_prog);
    cmd.args(common_args)
        .arg("--addr=127.0.0.1:8000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if samply_profiling || heaptrack_profiling {
        cmd.current_dir("./output_p0");
    }
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().unwrap();

    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();
    children.push(child);

    let (s, mut r) = channel(10);

    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move { output_server::server(s).await });
    });

    thread::spawn(move || {
        while let Some(Ok(line)) = stdout.next() {
            eprintln!("party0> {line}");
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("party0> {line}");
        }
    });

    let crate_dir: PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();
    let (pol0, pol1) = if use_big_input {
        (
            fs::read_to_string(crate_dir.join("policies/policy0-big.json")).unwrap(),
            fs::read_to_string(crate_dir.join("policies/policy1-big.json")).unwrap(),
        )
    } else {
        (
            fs::read_to_string(crate_dir.join("policies/policy0.json")).unwrap(),
            fs::read_to_string(crate_dir.join("policies/policy1.json")).unwrap(),
        )
    };
    #[derive(Deserialize)]
    struct PolicyProgram {
        program: String,
    }
    let pol0_program: PolicyProgram = serde_json::from_str(&pol0).expect("Invalid policy");
    let pol1_program: PolicyProgram = serde_json::from_str(&pol1).expect("Invalid policy");
    let expected_policy = fs::read_to_string(crate_dir.join(".example.garble.rs"))
        .expect("error reading example garble program");
    assert_eq!(expected_policy, pol0_program.program);
    assert_eq!(expected_policy, pol1_program.program);

    sleep(Duration::from_millis(millis));
    let client = reqwest::blocking::Client::new();
    thread::scope(|s| {
        // test that we can start party 0 before party 1
        s.spawn(|| {
            client
                .post("http://127.0.0.1:8000/schedule")
                .body(pol0)
                .header("Content-Type", "application/json")
                .timeout(Duration::from_secs(60 * 60))
                .send()
                .unwrap()
                .error_for_status()
                .unwrap();
        });
        thread::sleep(Duration::from_millis(100));
        s.spawn(|| {
            client
                .post("http://127.0.0.1:8001/schedule")
                .body(pol1)
                .header("Content-Type", "application/json")
                .send()
                .unwrap()
                .error_for_status()
                .unwrap();
        });
    });

    let result = r.blocking_recv().expect("output server crashed");
    eprintln!("Got result: {result:?}");

    // To properly write out profiling data, we need to send a SIGINT to the
    // child process group.
    #[cfg(unix)]
    {
        for child in children {
            nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(child.id() as i32),
                nix::sys::signal::SIGINT,
            )
            .unwrap();
        }
    }
    #[cfg(not(unix))]
    {
        for mut child in children {
            child.kill().unwrap();
        }
    }

    let expected_lit: Literal = if use_big_input {
        false.into()
    } else {
        true.into()
    };
    assert_eq!(MpcResult::Success(expected_lit), result);
}

/// A small server that listens for requests to the `/output` url and
/// returns those via an mpsc::channel.
mod output_server {
    use axum::{Json, Router, extract::State, routing::post};
    use garble_lang::literal::Literal;
    use serde::Deserialize;
    use tokio::sync::mpsc;

    pub(super) async fn server(sender: mpsc::Sender<MpcResult>) {
        let app = Router::new()
            .route("/output", post(output))
            .with_state(sender);

        // Run the server.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:8099")
            .await
            .unwrap();
        axum::serve(listener, app).await.unwrap();
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(tag = "type", content = "details")]
    #[serde(rename_all = "camelCase")]
    pub(super) enum MpcResult {
        Success(Literal),
        Error(serde_json::Value),
    }

    async fn output(State(sender): State<mpsc::Sender<MpcResult>>, Json(result): Json<MpcResult>) {
        sender.send(result).await.unwrap()
    }
}
