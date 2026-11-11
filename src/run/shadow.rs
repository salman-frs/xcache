use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

use super::report::Report;
use super::{Console, Execution};
use crate::digest::Digest;
use crate::observe::{Access, State};
use crate::outputs;
use crate::store::{Entry, Input, RunResult, Store};

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Correct,
    Nondeterministic,
    FalseHit,
}

pub struct Comparison {
    pub verdict: Verdict,
    pub differences: Vec<String>,
}

/// Compares a fresh run with the cached result it shadowed. Returns the cached
/// exit status when the cached result is left in place, as a hit would leave
/// it, or None when the fresh result is kept.
pub fn verify(
    cached: &Entry,
    fresh: &Execution,
    store: &Store,
    fingerprint: Digest,
    console: &Console,
    report: &mut Report,
) -> Option<i32> {
    let comparison = compare(cached, fresh);
    report.compared(&comparison);
    let details = comparison.differences.join("; ");
    match comparison.verdict {
        Verdict::Correct => console.say("shadow: the cached result matches a fresh run"),
        Verdict::Nondeterministic => console.say(format!(
            "shadow: the command read the same inputs but produced a different result, so it is nondeterministic: {details}"
        )),
        Verdict::FalseHit => {
            console.error(format!("shadow: FALSE HIT, the cached result differs from a fresh run: {details}"));
            if let Err(error) = store.remove(fingerprint, cached) {
                console.say(format!("could not remove the wrong cache entry ({error})"));
            }
            return None;
        }
    }
    match leave_cached_result(comparison.verdict, cached, fresh, store) {
        Ok(()) => Some(cached.result.exit_code),
        Err(error) => {
            console.say(format!("could not restore the cached result ({error:#}); keeping the fresh one"));
            None
        }
    }
}

fn compare(cached: &Entry, fresh: &Execution) -> Comparison {
    let differences = match &fresh.result {
        Some(result) => differences(&cached.result, result),
        None => fresh.reasons.iter().map(|reason| format!("fresh run is not cacheable: {reason}")).collect(),
    };
    if differences.is_empty() {
        return Comparison { verdict: Verdict::Correct, differences };
    }
    let unrecorded = unrecorded_inputs(cached, &fresh.inputs);
    if unrecorded.is_empty() {
        Comparison { verdict: Verdict::Nondeterministic, differences }
    } else {
        Comparison { verdict: Verdict::FalseHit, differences: unrecorded.into_iter().chain(differences).collect() }
    }
}

/// Leaves what a hit would have left, so the commands that follow see the same
/// files with and without --shadow.
fn leave_cached_result(verdict: Verdict, cached: &Entry, fresh: &Execution, store: &Store) -> Result<()> {
    if verdict != Verdict::Nondeterministic {
        return Ok(());
    }
    outputs::restore(&cached.result.outputs, store)?;
    let cached_paths: HashSet<&Path> = cached.result.outputs.iter().map(|output| output.path.as_path()).collect();
    let created_only_by_fresh_run = fresh.created.iter().filter(|path| !cached_paths.contains(path.as_path()));
    outputs::remove_created(created_only_by_fresh_run.rev())
}

/// Inputs the fresh run depended on that the cached run did not record, leaving
/// out absent paths, which differ for random temporary names, and files the
/// cached run recorded with that content or overwrote without looking.
fn unrecorded_inputs(cached: &Entry, fresh: &[Input]) -> Vec<String> {
    let recorded: HashMap<(Access, &Path), &State> =
        cached.inputs.iter().map(|input| ((input.access, input.path.as_path()), &input.state)).collect();
    let mut recorded_files: HashMap<&Path, Vec<&State>> = HashMap::new();
    for input in cached.inputs.iter().filter(|input| matches!(input.state, State::File { .. })) {
        recorded_files.entry(input.path.as_path()).or_default().push(&input.state);
    }
    let written: HashSet<&Path> = cached.result.outputs.iter().map(|output| output.path.as_path()).collect();

    let absent = |input: &Input| {
        matches!(
            input.state,
            State::Missing | State::Error { errno: libc::ENOTDIR } | State::Writable { is_dir: false, .. }
        )
    };
    let recorded_as_is = |input: &Input| {
        recorded.get(&(input.access, input.path.as_path())) == Some(&&input.state)
            || recorded_files.get(input.path.as_path()).is_some_and(|states| states.contains(&&input.state))
    };
    let looked_at: HashSet<&Path> = cached
        .inputs
        .iter()
        .filter(|input| input.access != Access::Writable && input.state != State::Missing)
        .map(|input| input.path.as_path())
        .collect();
    let written_blindly =
        |input: &Input| written.contains(input.path.as_path()) && !looked_at.contains(input.path.as_path());
    fresh
        .iter()
        .filter(|input| !absent(input) && !recorded_as_is(input) && !written_blindly(input))
        .map(|input| format!("{} ({:?}) was not recorded as {}", input.path.display(), input.access, input.state))
        .collect()
}

fn differences(cached: &RunResult, fresh: &RunResult) -> Vec<String> {
    let mut differences = Vec::new();
    if cached.exit_code != fresh.exit_code {
        differences.push(format!("exit status {} vs {}", cached.exit_code, fresh.exit_code));
    }
    if cached.stdio != fresh.stdio {
        differences.push("stdout/stderr differ".into());
    }
    let by_path = |result: &RunResult| -> BTreeMap<PathBuf, _> {
        result.outputs.iter().map(|output| (output.path.clone(), output.state.clone())).collect()
    };
    let (cached_outputs, fresh_outputs) = (by_path(cached), by_path(fresh));
    let paths: BTreeSet<&PathBuf> = cached_outputs.keys().chain(fresh_outputs.keys()).collect();
    for path in paths {
        match (cached_outputs.get(path), fresh_outputs.get(path)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(_), Some(_)) => differences.push(format!("{} differs", path.display())),
            (Some(_), None) => differences.push(format!("{} is only in the cached result", path.display())),
            (None, _) => differences.push(format!("{} is only in the fresh result", path.display())),
        }
    }
    differences
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Output, OutputState};

    fn file(content: &[u8]) -> State {
        State::File { size: content.len() as u64, mode: 0o644, content: Some(Digest::of_bytes(content)) }
    }

    fn read(path: &str, content: &[u8]) -> Input {
        Input { access: Access::Read, path: path.into(), state: file(content) }
    }

    fn result(output: &[u8]) -> RunResult {
        let state = OutputState::File { mode: 0o644, size: output.len() as u64, content: Digest::of_bytes(output) };
        let output = Output { path: "/out".into(), state, age_ns: 0, chosen_mtime_ns: None };
        RunResult { exit_code: 0, stdio: Digest::of_bytes(b""), outputs: vec![output] }
    }

    fn cached(inputs: Vec<Input>, output: &[u8]) -> Entry {
        Entry::new("cmd".into(), 1, inputs, result(output))
    }

    fn fresh(inputs: Vec<Input>, output: &[u8]) -> Execution {
        Execution {
            exit_code: 0,
            inputs,
            created: BTreeSet::new(),
            result: Some(result(output)),
            reasons: Vec::new(),
            traced: true,
            timings: Default::default(),
        }
    }

    fn verdict(cached: &Entry, fresh: &Execution) -> Verdict {
        compare(cached, fresh).verdict
    }

    #[test]
    fn the_same_result_is_correct() {
        let inputs = vec![read("/src/a", b"a")];
        assert_eq!(verdict(&cached(inputs.clone(), b"out"), &fresh(inputs, b"out")), Verdict::Correct);
    }

    #[test]
    fn a_different_result_from_the_same_inputs_is_nondeterministic() {
        let inputs = vec![read("/src/a", b"a")];
        assert_eq!(verdict(&cached(inputs.clone(), b"one"), &fresh(inputs, b"two")), Verdict::Nondeterministic);
    }

    #[test]
    fn a_different_result_from_an_unrecorded_input_is_a_false_hit() {
        let cached = cached(vec![read("/src/a", b"a")], b"one");
        let fresh = fresh(vec![read("/src/a", b"a"), read("/src/b", b"b")], b"two");
        let comparison = compare(&cached, &fresh);
        assert_eq!(comparison.verdict, Verdict::FalseHit);
        assert!(
            comparison.differences[0].starts_with("/src/b (Read) was not recorded"),
            "{:?}",
            comparison.differences
        );
    }

    #[test]
    fn missing_paths_only_the_fresh_run_checked_are_not_unrecorded_inputs() {
        let cached = cached(vec![read("/src/a", b"a")], b"one");
        let probe = Input { access: Access::Stat, path: "/tmp/random-1234".into(), state: State::Missing };
        let fresh = fresh(vec![read("/src/a", b"a"), probe], b"two");
        assert_eq!(verdict(&cached, &fresh), Verdict::Nondeterministic);
    }
}
