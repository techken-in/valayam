use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Valayam"));
}

#[test]
fn test_invalid_target() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.arg("scan")
        .arg("--target")
        .arg("invalid://not_a_url")
        .assert()
        .failure();
}
