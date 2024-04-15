use std::{
    io::{BufRead, BufReader},
    process::{exit, Command, Stdio},
    thread::{self, sleep},
    time::Duration,
};

#[test]
fn simulate() {
    let millis = 1000;
    println!("\n\n--- {millis}ms ---\n\n");
    let mut children = vec![];
    let mut cmd = Command::new("cargo")
        .args(["run", "--", "--port=8002", "--config=preprocessor.json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    sleep(Duration::from_millis(millis));
    let mut stdout = BufReader::new(cmd.stdout.take().unwrap()).lines();
    let mut stderr = BufReader::new(cmd.stderr.take().unwrap()).lines();
    thread::spawn(move || {
        while let Some(Ok(line)) = stdout.next() {
            println!("pre> {line}");
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("pre> {line}");
        }
    });
    children.push(cmd);
    for p in [1] {
        let port = format!("--port=800{p}");
        let config = format!("--config=policies{p}.json");
        let args = vec!["run", "--", &port, &config];
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
                println!("party{p}> {line}");
            }
        });
        thread::spawn(move || {
            while let Some(Ok(line)) = stderr.next() {
                eprintln!("party{p}> {line}");
            }
        });
        children.push(cmd);
    }
    sleep(Duration::from_millis(500));
    let args = vec!["run", "--", "--port=8000", "--config=policies0.json"];
    let mut cmd = Command::new("cargo")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(cmd.stdout.take().unwrap()).lines();
    let mut stderr = BufReader::new(cmd.stderr.take().unwrap()).lines();
    children.push(cmd);
    thread::spawn(move || {
        while let Some(Ok(line)) = stdout.next() {
            println!("party0> {line}");
            if line == "Output is 5u32" {
                exit(0);
            }
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("party0> {line}");
        }
    });
    sleep(Duration::from_secs(10));
    eprintln!("Test did not complete!");
    for mut child in children {
        child.kill().unwrap();
    }
    exit(-1);
}
