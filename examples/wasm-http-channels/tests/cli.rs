use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread::{self, sleep},
    time::Duration,
};

const URLS: &str = "http://127.0.0.1:8000;http://127.0.0.1:8001;http://127.0.0.1:8002";

#[test]
fn simulate() {
    for millis in [50, 500, 2_000, 10_000] {
        println!("\n\n--- {millis}ms ---\n\n");
        let mut children = vec![];
        for p in [1, 2] {
            let party_arg = format!("--party={p}");
            let args = vec![
                "run",
                "--release",
                "--",
                URLS,
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
            children.push(cmd);
            sleep(Duration::from_millis(millis));
        }
        let args = vec![
            "run",
            "--release",
            "--",
            URLS,
            "--program=.add.garble.rs",
            "--input=2u32",
            "--party=0",
        ];
        let out = Command::new("cargo").args(args).output().unwrap();
        eprintln!("{}", String::from_utf8(out.stderr).unwrap());
        let out = String::from_utf8(out.stdout).unwrap();
        let out = out.lines().last().unwrap_or_default();
        for mut child in children {
            child.kill().unwrap();
        }
        if out == "The result is 6u32" {
            return;
        } else {
            eprintln!("Last line is '{out}'");
            sleep(Duration::from_millis(millis));
            println!("Could not complete test successfully, trying again with more time...");
        }
    }
    panic!("Test failed repeatedly!");
}
