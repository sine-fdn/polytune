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
use tokio::sync::mpsc::channel;

use crate::common::output_server::{self, MpcResult};

mod common;

/// This test supports profiling with heaptrack or samply if installed by setting the corresponding
/// env variables. By setting the `POLYTUNE_TEST_BIG` variable, policies with a larger input
/// will be used.
#[test]
fn test_and_profile_server() {
    let millis = 2000;
    println!("\n\n--- {millis}ms ---\n\n");
    let mut children = vec![];
    let use_big_input = env::var("POLYTUNE_TEST_BIG").is_ok();
    let heaptrack_profiling = env::var("POLYTUNE_TEST_HEAPTRACK").is_ok();
    let samply_profiling = env::var("POLYTUNE_TEST_SAMPLY").is_ok();
    let polytune_bin = PathBuf::from(env!("CARGO_BIN_EXE_polytune-http-server"));
    let crate_dir: PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();

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
    let jwt_key_arg = format!(
        "--jwt-key={}",
        crate_dir.join("test_key/test-private.pem").display()
    );
    common_args.extend([
        &jwt_key_arg,
        "--jwt-iss=polytune",
        "--jwt-exp=1",
        r#"--jwt-claims={"roles": ["TEST_ROLE"]}"#,
    ]);

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

        rt.block_on(async move {
            output_server::server(s, Some("127.0.0.1:8099"))
                .await
                .1
                .await
        });
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

    let (_id, result) = r.blocking_recv().expect("output server crashed");
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
