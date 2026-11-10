use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::digest::ContentHasher;
use crate::invocation::Invocation;
use crate::observe::{self, Access, State};
use crate::outputs;
use crate::record::Recorder;
use crate::store::{Entry, Input, RunResult, Store, unix_now};
use crate::trace::{self, Exit, Outcome};

pub struct RunOptions {
    pub argv: Vec<OsString>,
    pub pass_env: Vec<String>,
    pub store_dir: PathBuf,
    pub shadow: bool,
    pub report: Option<PathBuf>,
    pub quiet: bool,
}

#[derive(Serialize, Default)]
struct Report {
    outcome: ReportOutcome,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<String>,
    fingerprint: String,
    exit_code: i32,
    inputs: usize,
    outputs: usize,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow: Option<ShadowVerdict>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    differences: Vec<String>,
    timings_ms: Timings,
}

#[derive(Serialize, Default, Clone, Copy)]
struct Timings {
    lookup: u64,
    command: u64,
    hashing: u64,
    store: u64,
}

#[derive(Serialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReportOutcome {
    #[default]
    Miss,
    Hit,
    NotCached,
    Untraced,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ShadowVerdict {
    Correct,
    Nondeterministic,
    FalseHit,
}

struct Execution {
    exit_code: i32,
    inputs: Vec<Input>,
    result: Option<RunResult>,
    reasons: Vec<String>,
    traced: bool,
    timings: Timings,
}

pub fn run(options: RunOptions) -> Result<i32> {
    let started = Instant::now();
    let invocation =
        Invocation::new(options.argv.clone(), std::env::current_dir()?, std::env::vars_os(), &options.pass_env);
    let fingerprint = invocation.fingerprint();
    let mut report = Report { fingerprint: fingerprint.to_hex(), ..Report::default() };
    let say = |message: String| {
        if !options.quiet {
            eprintln!("xcache: {message}");
        }
    };

    let store = match Store::open(options.store_dir.clone()) {
        Ok(store) => store,
        Err(error) => {
            say(format!("cache directory unavailable ({error}); running without cache"));
            return run_untraced(&invocation);
        }
    };
    let mut hasher = ContentHasher::load(store.stat_cache_path());
    let entries = store.entries(fingerprint).unwrap_or_else(|error| {
        say(format!("ignoring unreadable cache entries ({error})"));
        Vec::new()
    });
    let mut hit = entries.iter().find(|entry| first_mismatch(entry, &mut hasher).is_none());
    report.timings_ms.lookup = started.elapsed().as_millis() as u64;

    if let Some(entry) = hit
        && !options.shadow
    {
        match replay(entry, &store) {
            Ok(()) => {
                let _ = store.mark_used(fingerprint, entry.created_at);
                let _ = hasher.save();
                say(format!(
                    "hit, restored {} (the original run took {})",
                    count(entry.result.outputs.len(), "output"),
                    human_duration(Duration::from_millis(entry.duration_ms))
                ));
                report.outcome = ReportOutcome::Hit;
                report.exit_code = entry.result.exit_code;
                report.inputs = entry.inputs.len();
                report.outputs = entry.result.outputs.len();
                report.duration_ms = started.elapsed().as_millis() as u64;
                write_report(&options.report, &report)?;
                return Ok(entry.result.exit_code);
            }
            Err(error) => {
                say(format!("could not restore the cached result ({error:#}); running the command"));
                hit = None;
            }
        }
    }

    let execution = execute(&invocation, &store, &mut hasher)?;
    let duration = started.elapsed();
    report.timings_ms = Timings { lookup: report.timings_ms.lookup, ..execution.timings };
    report.exit_code = execution.exit_code;
    report.inputs = execution.inputs.len();
    report.outputs = execution.result.as_ref().map_or(0, |result| result.outputs.len());
    report.reasons = execution.reasons.clone();
    report.outcome = match (&execution.result, execution.traced) {
        _ if hit.is_some() => ReportOutcome::Hit,
        (_, false) => ReportOutcome::Untraced,
        (Some(_), true) => ReportOutcome::Miss,
        (None, true) => ReportOutcome::NotCached,
    };

    if let Some(cached) = hit {
        let (verdict, differences) = shadow_verdict(cached, &execution);
        report.shadow = Some(verdict);
        report.differences = differences;
        let details = report.differences.join("; ");
        match verdict {
            ShadowVerdict::Correct => say("shadow: the cached result matches a fresh run".into()),
            ShadowVerdict::Nondeterministic => say(format!(
                "shadow: the command read the same inputs but produced a different result, so it is nondeterministic: {details}"
            )),
            ShadowVerdict::FalseHit => {
                eprintln!("xcache: shadow: FALSE HIT, the cached result differs from a fresh run: {details}");
                if let Err(error) = store.remove(fingerprint, cached) {
                    say(format!("could not remove the wrong cache entry ({error})"));
                }
            }
        }
        if verdict != ShadowVerdict::FalseHit {
            match leave_cached_result(verdict, cached, &store) {
                Ok(()) => {
                    let _ = store.mark_used(fingerprint, cached.created_at);
                    let _ = hasher.save();
                    report.exit_code = cached.result.exit_code;
                    report.duration_ms = duration.as_millis() as u64;
                    write_report(&options.report, &report)?;
                    return Ok(cached.result.exit_code);
                }
                Err(error) => say(format!("could not restore the cached result ({error:#}); keeping the fresh one")),
            }
        }
    }

    match execution.result {
        Some(result) => {
            let (input_count, output_count) = (execution.inputs.len(), result.outputs.len());
            let entry = Entry::new(invocation.display_command(), duration.as_millis() as u64, execution.inputs, result);
            match store.record(fingerprint, entry) {
                Ok(()) if hit.is_some() => {}
                Ok(()) => {
                    say(format!("miss, cached {} and {}", count(input_count, "input"), count(output_count, "output")))
                }
                Err(error) => say(format!("not cached: could not write the cache entry ({error})")),
            }
        }
        None if execution.traced => say(format!("not cached: {}", summarize(&execution.reasons))),
        None => {}
    }
    let _ = hasher.save();
    report.duration_ms = duration.as_millis() as u64;
    write_report(&options.report, &report)?;
    Ok(execution.exit_code)
}

pub fn explain(argv: Vec<OsString>, pass_env: &[String], store_dir: PathBuf) -> Result<()> {
    let invocation = Invocation::new(argv, std::env::current_dir()?, std::env::vars_os(), pass_env);
    let fingerprint = invocation.fingerprint();
    let store = Store::open(store_dir)?;
    let entries = store.entries(fingerprint)?;
    println!("command fingerprint {fingerprint}");
    if entries.is_empty() {
        println!("no cached runs for this exact command line, working directory and environment");
        return Ok(());
    }
    let mut hasher = ContentHasher::load(store.stat_cache_path());
    for (index, entry) in entries.iter().enumerate() {
        let age = human_duration(Duration::from_secs(unix_now().saturating_sub(entry.created_at)));
        print!("entry {} (cached {age} ago, {}): ", index + 1, count(entry.inputs.len(), "input"));
        match first_mismatch(entry, &mut hasher) {
            None => println!("would hit"),
            Some((input, current)) => println!(
                "{} changed ({:?}): was {}, now {}",
                input.path.display(),
                input.access,
                describe(&input.state),
                describe(&current)
            ),
        }
    }
    Ok(())
}

fn execute(invocation: &Invocation, store: &Store, hasher: &mut ContentHasher) -> Result<Execution> {
    let store_root = fs::canonicalize(store.root()).unwrap_or_else(|_| store.root().to_path_buf());
    let recorder = Recorder::new(hasher, &[store_root.as_path()]);
    match trace::run(invocation, recorder)? {
        Outcome::Unavailable { reason } => {
            eprintln!("xcache: tracing is unavailable ({reason}); running without cache");
            let exit_code = run_untraced(invocation)?;
            Ok(Execution {
                exit_code,
                inputs: Vec::new(),
                result: None,
                reasons: vec![reason],
                traced: false,
                timings: Timings::default(),
            })
        }
        Outcome::ExecFailed { errno } => {
            let program = invocation.argv[0].to_string_lossy();
            let error = std::io::Error::from_raw_os_error(errno);
            let exit_code = if errno == libc::ENOENT { 127 } else { 126 };
            eprintln!("xcache: {program}: {error}");
            Ok(Execution {
                exit_code,
                inputs: Vec::new(),
                result: None,
                reasons: vec![error.to_string()],
                traced: true,
                timings: Timings::default(),
            })
        }
        Outcome::Ran(traced) => {
            let mut reasons = traced.recording.taints.clone();
            match traced.exit {
                Exit::Code(0) => {}
                Exit::Code(code) => reasons.push(format!("exited with status {code}")),
                Exit::Signal(signal) => reasons.push(format!("was killed by signal {signal}")),
            }
            let storing = Instant::now();
            let result = if reasons.is_empty() {
                let captured = outputs::capture(&traced.recording, store).and_then(|outputs| {
                    let stdio = store.put_bytes(&traced.stdio).context("storing output")?;
                    Ok(RunResult { exit_code: 0, stdio, outputs })
                });
                captured.map_err(|error| reasons.push(format!("{error:#}"))).ok()
            } else {
                None
            };
            let timings = Timings {
                lookup: 0,
                command: traced.command_time.as_millis() as u64,
                hashing: traced.hashing_time.as_millis() as u64,
                store: storing.elapsed().as_millis() as u64,
            };
            Ok(Execution {
                exit_code: traced.exit.code(),
                inputs: traced.recording.inputs,
                result,
                reasons,
                traced: true,
                timings,
            })
        }
    }
}

fn replay(entry: &Entry, store: &Store) -> Result<()> {
    let stdio = store.read_blob(entry.result.stdio).context("reading recorded output")?;
    outputs::restore(&entry.result.outputs, store)?;
    trace::replay_output(&stdio).context("replaying output")?;
    Ok(())
}

fn run_untraced(invocation: &Invocation) -> Result<i32> {
    let status = Command::new(&invocation.argv[0])
        .args(&invocation.argv[1..])
        .env_clear()
        .envs(invocation.env.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("running {}", invocation.argv[0].to_string_lossy()))?;
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

fn first_mismatch<'e>(entry: &'e Entry, hasher: &mut ContentHasher) -> Option<(&'e Input, State)> {
    entry.inputs.iter().find_map(|input| {
        let current = observe::probe(input.access, &input.path, hasher);
        (current != input.state).then_some((input, current))
    })
}

/// Leaves what a hit would have left, so the commands that follow see the same
/// files with and without --shadow.
fn leave_cached_result(verdict: ShadowVerdict, cached: &Entry, store: &Store) -> Result<()> {
    if verdict == ShadowVerdict::Nondeterministic {
        outputs::restore(&cached.result.outputs, store)?;
    }
    Ok(())
}

fn shadow_verdict(cached: &Entry, execution: &Execution) -> (ShadowVerdict, Vec<String>) {
    let differences = match &execution.result {
        Some(fresh) => differences(&cached.result, fresh),
        None => execution.reasons.iter().map(|reason| format!("fresh run is not cacheable: {reason}")).collect(),
    };
    if differences.is_empty() {
        return (ShadowVerdict::Correct, differences);
    }
    let unrecorded = unrecorded_inputs(&cached.inputs, &execution.inputs);
    if unrecorded.is_empty() {
        (ShadowVerdict::Nondeterministic, differences)
    } else {
        (ShadowVerdict::FalseHit, unrecorded.into_iter().chain(differences).collect())
    }
}

/// Inputs the fresh run depended on that the cached run did not record.
/// Probes of paths that did not exist are left out: tools pick random names for
/// temporary files, so each run probes different absent paths.
fn unrecorded_inputs(cached: &[Input], fresh: &[Input]) -> Vec<String> {
    let recorded: HashMap<(Access, &Path), &State> =
        cached.iter().map(|input| ((input.access, input.path.as_path()), &input.state)).collect();
    fresh
        .iter()
        .filter(|input| !matches!(input.state, State::Missing | State::Writable { is_dir: false, .. }))
        .filter(|input| recorded.get(&(input.access, input.path.as_path())) != Some(&&input.state))
        .map(|input| {
            format!("{} ({:?}) was not recorded as {}", input.path.display(), input.access, describe(&input.state))
        })
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

fn describe(state: &State) -> String {
    match state {
        State::Missing => "missing".into(),
        State::File { size, mode, content } => {
            format!("{size}-byte file {} with mode {mode:o}", &content.to_hex()[..12])
        }
        State::Dir { real_path, mode } => format!("directory {} with mode {mode:o}", real_path.display()),
        State::Listing { entries, .. } => format!("listing {}", &entries.to_hex()[..12]),
        State::Symlink { target } => format!("symlink to {}", target.display()),
        State::Writable { parent_is_dir, is_dir } => format!("parent_is_dir={parent_is_dir} is_dir={is_dir}"),
        State::Special { kind } => format!("{kind:?}").to_lowercase(),
        State::Error { errno } => std::io::Error::from_raw_os_error(*errno).to_string(),
    }
}

fn count(n: usize, noun: &str) -> String {
    if n == 1 { format!("1 {noun}") } else { format!("{n} {noun}s") }
}

fn summarize(reasons: &[String]) -> String {
    match reasons {
        [] => "unknown reason".into(),
        [only] => only.clone(),
        [first, rest @ ..] => format!("{first} (and {} more)", rest.len()),
    }
}

fn human_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    match seconds {
        s if s < 1.0 => format!("{}ms", duration.as_millis()),
        s if s < 10.0 => format!("{s:.1}s"),
        s if s < 120.0 => format!("{s:.0}s"),
        s if s < 7200.0 => format!("{:.0}m", s / 60.0),
        s => format!("{:.0}h", s / 3600.0),
    }
}

fn write_report(path: &Option<PathBuf>, report: &Report) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let json = serde_json::to_vec_pretty(report)?;
    fs::write(Path::new(path), json).with_context(|| format!("writing report {}", path.display()))
}
