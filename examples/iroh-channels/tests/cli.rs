use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

#[test]
fn simulate() {
    let mut cmd = Command::new("cargo")
        .args(["run", "--", "pre", "--parties=3"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(cmd.stdout.take().unwrap()).lines().skip(4);
    let mut stderr = BufReader::new(cmd.stderr.take().unwrap()).lines();
    let join_cmd = stdout.next().unwrap().unwrap();
    println!("Joining using the following cmd: {join_cmd}");
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
    let mut join_args: Vec<_> = join_cmd.split(" ").skip(1).collect();
    for p in [1, 2] {
        let party_arg = format!("--party={p}");
        let mut args = join_args.clone();
        args.push(&party_arg);
        args.push("--program=.add.garble.rs".into());
        args.push("--input=2u32".into());
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
    join_args.push("--party=0");
    join_args.push("--program=.add.garble.rs");
    join_args.push("--input=2u32");
    let out = Command::new("cargo").args(join_args).output().unwrap();
    eprintln!("{}", String::from_utf8(out.stderr).unwrap());
    let out = String::from_utf8(out.stdout).unwrap();
    let out = out.lines().last().unwrap_or_default();
    assert_eq!("The result is 6u32", out);
}
