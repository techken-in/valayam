use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_with_target_flag() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.args(["-u", "https://example.com", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("target"));
}

#[test]
fn test_cli_with_template_flag() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.args(["-t", "templates_repo/demo-template.yaml", "--help"])
        .assert()
        .success();
}

#[test]
fn test_cli_with_output_flag() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.args(["-o", "results.jsonl", "--help"])
        .assert()
        .success();
}

#[test]
fn test_cli_plugin_init_subcommand() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.args(["plugin", "init", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("name"))
        .stdout(predicate::str::contains("lang"))
        .stdout(predicate::str::contains("runtime"));
}

#[test]
fn test_cli_plugin_generate_key_subcommand() {
    let mut cmd = Command::cargo_bin("valayam-cli").unwrap();
    cmd.args(["plugin", "generate-key", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("output"));
}
