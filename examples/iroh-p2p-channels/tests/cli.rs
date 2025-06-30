use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

#[test]
fn simulate() {
    let mut cmd = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--",
            "--wait-time=1",
            "--program=.add.garble.rs",
            "--party=2",
            "--input=2",
            "new",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(cmd.stdout.take().unwrap()).lines().skip(4);
    let mut stderr = BufReader::new(cmd.stderr.take().unwrap()).lines();
    println!("Trying to get the ticket so that others can join...");
    let ticket = stdout.next().unwrap().unwrap();
    let ticket_prefix = "> ticket to join us: ";
    let ticket = if ticket.starts_with(ticket_prefix) {
        ticket.replace(ticket_prefix, "")
    } else {
        panic!("Expected a ticket but found: {ticket}");
    };
    thread::spawn(move || {
        while let Some(Ok(line)) = stdout.next() {
            println!("party2> {line}");
        }
    });
    thread::spawn(move || {
        while let Some(Ok(line)) = stderr.next() {
            eprintln!("party2> {line}");
        }
    });
    let mut cmd = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--",
            "--wait-time=1",
            "--program=.add.garble.rs",
            "--party=1",
            "--input=2",
            "join",
            &ticket,
        ])
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
    let out = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--",
            "--wait-time=1",
            "--program=.add.garble.rs",
            "--party=0",
            "--input=2",
            "join",
            &ticket,
        ])
        .output()
        .unwrap();
    eprintln!("{}", String::from_utf8(out.stderr).unwrap());
    let out = String::from_utf8(out.stdout).unwrap();
    let out = out.lines().last().unwrap_or_default();
    cmd.kill().unwrap();
    assert_eq!("The result is 6", out);
}
