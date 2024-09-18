use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread::{self, sleep},
    time::Duration,
};

const ENDPOINT: &str = "http://127.0.0.1:8000";

#[test]
fn simulate() {
    let mut child = Command::new("cargo")
        .args(["run", "--release", "--", "serve"])
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(500));
    let mut cmd = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--",
            "pre",
            ENDPOINT,
            "--session=test",
            "--parties=3",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(500));
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
    for p in [1, 2] {
        let party_arg = format!("--party={p}");
        let args = vec![
            "run",
            "--release",
            "--",
            "party",
            ENDPOINT,
            "--session=test",
            "--program=.add.garble.rs",
            "--input=2u32",
            &party_arg,
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
                println!("party{p}> {line}");
            }
        });
        thread::spawn(move || {
            while let Some(Ok(line)) = stderr.next() {
                eprintln!("party{p}> {line}");
            }
        });
    }
    let args = vec![
        "run",
        "--release",
        "--",
        "party",
        ENDPOINT,
        "--session=test",
        "--program=.add.garble.rs",
        "--input=2u32",
        "--party=0",
    ];
    let out = Command::new("cargo").args(args).output().unwrap();
    eprintln!("{}", String::from_utf8(out.stderr).unwrap());
    let out = String::from_utf8(out.stdout).unwrap();
    let out = out.lines().last().unwrap_or_default();
    child.kill().unwrap();
    assert_eq!("The result is 6u32", out);
}
