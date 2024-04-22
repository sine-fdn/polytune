use std::{
    io::{BufRead, BufReader},
    process::{exit, Command, Stdio},
    sync::mpsc::channel,
    thread::{self, sleep},
    time::Duration,
};

#[test]
fn simulate() {
    let millis = 1000;
    println!("\n\n--- {millis}ms ---\n\n");
    let mut children = vec![];
    let mut cmd = Command::new("cargo")
        .args(["run", "--", "--port=8003", "--config=preprocessor.json"])
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
    for p in [1, 2] {
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
    let (s, r) = channel::<()>();
    thread::spawn(move || {
        while let Some(Ok(line)) = stdout.next() {
            println!("party0> {line}");
            if line.starts_with("MPC Output:") {
                return s.send(()).unwrap();
            }
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("party0> {line}");
        }
    });
    let result = r.recv_timeout(Duration::from_secs(300));
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
