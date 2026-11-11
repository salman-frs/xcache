use std::fs;
use std::io::Write;
use std::process::Stdio;

use serde_json::Value;

use crate::support::{Workspace, assert_outcome};

#[test]
fn environment_changes_miss_and_volatile_variables_are_hidden() {
    let ws = Workspace::new();
    let run = |mode: &str, sha: &str| {
        ws.run_with(&["sh", "-c", "echo \"$MODE $GITHUB_SHA\" > out.txt"], |xcache| {
            xcache.env("MODE", mode).env("GITHUB_SHA", sha);
        })
    };
    assert_outcome(&run("debug", "a"), "miss");
    assert_outcome(&run("debug", "b"), "hit");
    assert_eq!(ws.read("out.txt"), "debug \n");
    assert_outcome(&run("release", "b"), "miss");
}

#[test]
fn stdin_is_not_an_input() {
    let ws = Workspace::new();
    let run = |input: &str| {
        let report = ws.dir.path().join("stdin-report.json");
        let mut child = ws
            .xcache()
            .args(["run", "--report"])
            .arg(&report)
            .args(["--", "sh", "-c", "cat > out.txt"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        child.wait().unwrap();
        serde_json::from_slice::<Value>(&fs::read(&report).unwrap()).unwrap()["outcome"].clone()
    };
    assert_eq!(run("first"), "miss");
    assert_eq!(run("second"), "hit");
    assert_eq!(ws.read("out.txt"), "");
}
