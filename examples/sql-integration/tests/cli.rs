use std::{
    io::{BufRead, BufReader},
    process::{exit, Command, Stdio},
    sync::mpsc::channel,
    thread::{self, sleep},
    time::Duration,
};

#[test]
fn simulate() {
    let millis = 2000;
    println!("\n\n--- {millis}ms ---\n\n");
    let mut children = vec![];
    let args = vec![
        "run",
        "--release",
        "--",
        "--port=8001",
        "--config=policy1.json",
    ];
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
    let args = vec![
        "run",
        "--release",
        "--",
        "--port=8000",
        "--config=policy0.json",
    ];
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
            if line.contains("MPC Output: 1 rows") {
                return s.send(()).unwrap();
            }
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("party0> {line}");
        }
    });
    let result = r.recv_timeout(Duration::from_secs(60 * 60));
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
