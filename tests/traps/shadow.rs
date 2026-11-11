use std::fs;

use crate::support::{Workspace, assert_outcome};

#[test]
fn shadow_mode_confirms_hits_and_catches_nondeterminism() {
    let ws = Workspace::new();
    ws.write("in.txt", "x");
    let deterministic = ["sh", "-c", "cat in.txt > out.txt"];
    assert_outcome(&ws.run(&deterministic), "miss");
    let confirmed = ws.shadow(&deterministic);
    assert_eq!(confirmed.report["shadow"], "correct", "{}", confirmed.report);

    let clock = ["sh", "-c", "date +%s%N > stamp.txt"];
    assert_outcome(&ws.run(&clock), "miss");
    let caught = ws.shadow(&clock);
    assert_eq!(caught.report["shadow"], "nondeterministic", "{}", caught.report);
}

#[test]
fn shadow_mode_leaves_what_a_hit_would_so_later_commands_see_the_same_files() {
    let ws = Workspace::new();
    let stamp = ["sh", "-c", "date +%s%N > stamp.txt"];
    let copy = ["sh", "-c", "cat stamp.txt > copy.txt"];
    assert_outcome(&ws.run(&stamp), "miss");
    assert_outcome(&ws.run(&copy), "miss");
    let cached_stamp = ws.read("stamp.txt");

    let shadowed = ws.shadow(&stamp);
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
    assert_eq!(ws.read("stamp.txt"), cached_stamp);

    let downstream = ws.shadow(&copy);
    assert_eq!(downstream.report["shadow"], "correct", "{}", downstream.report);
}

#[test]
fn shadow_mode_removes_files_only_the_fresh_run_created() {
    let ws = Workspace::new();
    let script = "mkdir -p out && touch out/$(date +%s%N)";
    assert_outcome(&ws.sh(script), "miss");
    let cached: Vec<_> = fs::read_dir(ws.path("out")).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    fs::remove_dir_all(ws.path("out")).unwrap();

    let shadowed = ws.shadow(&["sh", "-c", script]);
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
    let left: Vec<_> = fs::read_dir(ws.path("out")).unwrap().map(|entry| entry.unwrap().file_name()).collect();
    assert_eq!(left, cached);
}

#[test]
fn reading_a_file_the_cached_run_wrote_is_not_a_false_hit() {
    let ws = Workspace::new();
    ws.write("config.in", "v1");
    ws.write("config.out", "v1");
    ws.set_age("config.out", 200);
    ws.set_age("config.in", 100);
    let build =
        "if [ config.in -nt config.out ]; then rm config.out; cp config.in config.out; fi; cat config.out > result";
    assert_outcome(&ws.sh(build), "miss");

    ws.set_age("config.in", 300);
    let shadowed = ws.shadow(&["sh", "-c", build]);
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
}

#[test]
fn reading_what_the_cached_run_only_checked_is_not_a_false_hit() {
    let ws = Workspace::new();
    ws.write("data.txt", "same");
    ws.write("marker", "");
    ws.set_age("data.txt", 200);
    ws.set_age("marker", 100);
    let build = "if [ data.txt -nt marker ]; then read line < data.txt; test -e data.txt/sub; \
                 else test -s data.txt; fi; date +%s%N > built";
    assert_outcome(&ws.sh(build), "miss");

    ws.set_age("data.txt", 50);
    let shadowed = ws.shadow(&["sh", "-c", build]);
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
}

#[test]
fn reading_a_file_the_cached_run_overwrote_unseen_is_not_a_false_hit() {
    let ws = Workspace::new();
    ws.write("src.txt", "");
    ws.write("marker", "");
    ws.write("fingerprint", "old");
    ws.set_age("marker", 200);
    ws.set_age("src.txt", 100);
    let build = "if [ src.txt -nt marker ]; then echo new > fingerprint; else read seen < fingerprint; fi; \
                 date +%s%N > stamp";
    assert_outcome(&ws.sh(build), "miss");

    ws.write("fingerprint", "old");
    ws.set_age("src.txt", 300);
    let shadowed = ws.shadow(&["sh", "-c", build]);
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
}

#[test]
fn a_fresh_failure_with_the_same_inputs_is_nondeterministic_not_a_false_hit() {
    let ws = Workspace::new();
    let counter = ws.store.path().join("runs");
    fs::write(&counter, "0").unwrap();
    let flaky = format!("n=$(cat {0}); echo $((n + 1)) > {0}; test $n -eq 0", counter.display());
    assert_outcome(&ws.sh(&flaky), "miss");

    let shadowed = ws.shadow(&["sh", "-c", &flaky]);
    assert_eq!(shadowed.report["shadow"], "nondeterministic", "{}", shadowed.report);
    assert_eq!(shadowed.status, 0);
}
