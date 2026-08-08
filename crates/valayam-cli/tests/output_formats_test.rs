use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn test_cli_invalid_flag() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.arg("--nonexistent-flag")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn test_cli_conflicting_flags() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.args(["-t", "template.yaml", "-n", "nuclei.yaml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

#[test]
fn test_cli_help_contains_flags() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--target"))
        .stdout(predicate::str::contains("--template"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--rate-limit"))
        .stdout(predicate::str::contains("--concurrency"));
}

#[test]
fn test_cli_default_target() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("https://httpbin.org"));
}
