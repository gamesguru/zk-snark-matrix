//! CLI integration tests — spawns the binary and asserts on output.

use assert_cmd::Command;
use predicates::prelude::*;

const FIXTURE: &str = "../fixtures/fed_nutra_dev.json";

fn cmd() -> Command {
    Command::cargo_bin("ruma-zk-prover").expect("binary exists")
}

#[test]
fn cli_fingerprint() {
    cmd()
        .arg("fingerprint")
        .assert()
        .success()
        .stdout(predicate::str::contains("Circuit VK Hash:"));
}

#[test]
fn cli_witness_from_file() {
    cmd()
        .args(["witness", "-i", FIXTURE])
        .assert()
        .success()
        .stdout(predicate::str::contains("Events loaded: 254"))
        .stdout(predicate::str::contains(
            "[ok] All routing constraints satisfied",
        ))
        .stdout(predicate::str::contains("✓"));
}

#[test]
fn cli_witness_from_stdin() {
    let fixture = std::fs::read(FIXTURE).expect("fixture exists");
    cmd()
        .arg("witness")
        .write_stdin(fixture)
        .assert()
        .success()
        .stdout(predicate::str::contains("Events loaded: 254"))
        .stdout(predicate::str::contains("✓"));
}

#[test]
fn cli_witness_with_limit() {
    cmd()
        .args(["witness", "-i", FIXTURE, "-l", "16"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Events loaded: 16"));
}

#[test]
fn cli_no_args_shows_help() {
    cmd()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}
