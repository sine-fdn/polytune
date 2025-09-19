use std::{
    env, fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio, exit},
    sync::mpsc::channel,
    thread::{self, sleep},
    time::Duration,
};

use serde::Deserialize;

#[test]
fn simulate() {
    let millis = 2000;
    println!("\n\n--- {millis}ms ---\n\n");
    let mut children = vec![];
    let use_big_input = env::var("POLYTUNE_API_INTEGRATION_BIG").is_ok();
    let heaptrack_profiling = env::var("POLYTUNE_API_INTEGRATION_HEAPTRACK").is_ok();
    let polytune_bin =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("../debug-release/polytune-server");
    let cmd_prog = if heaptrack_profiling {
        "heaptrack".into()
    } else {
        polytune_bin.clone()
    };
    let common_args = if heaptrack_profiling {
        vec!["--record-only", polytune_bin.to_str().unwrap()]
    } else {
        vec![]
    };
    let mut cmd = Command::new(&cmd_prog)
        .args(common_args.clone())
        .arg("--port=8001")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(cmd.stdout.take().unwrap()).lines().skip(4);
    let mut stderr = BufReader::new(cmd.stderr.take().unwrap()).lines();
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
    children.push(cmd);

    sleep(Duration::from_millis(millis));

    let mut cmd = Command::new(cmd_prog)
        .args(common_args)
        .arg("--port=8000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(cmd.stdout.take().unwrap()).lines();
    let mut stderr = BufReader::new(cmd.stderr.take().unwrap()).lines();
    children.push(cmd);
    let (s, r) = channel::<()>();
    thread::spawn(move || {
        while let Some(Ok(line)) = stdout.next() {
            println!("party0> {line}");
            if use_big_input {
                let false_match = "(false, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])";
                let expected_literal = vec![false_match; 1000 + 1000 - 1].join(", ");
                let expected_msg = format!("[{expected_literal}]");
                if line.contains(&expected_msg) {
                    return s.send(()).unwrap();
                }
            } else if line.contains("Sending [(false, [0]), (false, [0]), (false, [0]), (true, [0]), (true, [1]), (true, [2])] to http://localhost:8002/output") {
                return s.send(()).unwrap();
            }
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("party0> {line}");
        }
    });

    let client = reqwest::blocking::Client::new();
    let crate_dir: PathBuf = env!("CARGO_MANIFEST_DIR").parse().unwrap();
    let (pol0, pol1) = if use_big_input {
        (
            fs::read_to_string(crate_dir.join("policy0-big.json")).unwrap(),
            fs::read_to_string(crate_dir.join("policy1-big.json")).unwrap(),
        )
    } else {
        (
            fs::read_to_string(crate_dir.join("policy0.json")).unwrap(),
            fs::read_to_string(crate_dir.join("policy1.json")).unwrap(),
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

    client
        .post("http://127.0.0.1:8001/launch")
        .body(pol1)
        .header("Content-Type", "application/json")
        .send()
        .unwrap();

    sleep(Duration::from_millis(millis));
    let client = reqwest::blocking::Client::new();
    client
        .post("http://127.0.0.1:8000/launch")
        .body(pol0)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(60 * 60))
        .send()
        .unwrap();

    let result = r.recv_timeout(Duration::from_secs(10));
    for mut child in children {
        child.kill().unwrap();
    }
    match result {
        Ok(_) => exit(0),
        Err(_) => {
            eprintln!("Test did not complete!");
            exit(-1);
        }
    }
}
