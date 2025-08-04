use std::{
    env, fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio, exit},
    sync::mpsc::channel,
    thread::{self, sleep},
    time::Duration,
};

#[test]
fn simulate() {
    let millis = 2000;
    println!("\n\n--- {millis}ms ---\n\n");
    let mut children = vec![];
    let use_big_input = env::var("POLYTUNE_API_INTEGRATION_BIG").is_ok();
    let args = vec!["run", "--release", "--", "--port=8001"];
    let mut cmd = Command::new("cargo")
        .args(args)
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
    let args = vec!["run", "--release", "--", "--port=8000"];
    let mut cmd = Command::new("cargo")
        .args(args)
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
            if use_big_input && line.contains("(true, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])") ||
                !use_big_input && line.contains("Sending [(false, [0]), (false, [0]), (false, [0]), (true, [0]), (true, [1]), (true, [2])] to http://localhost:8002/output") {
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
