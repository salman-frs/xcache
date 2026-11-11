mod execute;
mod report;
mod shadow;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::Display;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::digest::ContentHasher;
use crate::invocation::Invocation;
use crate::observe::{self, State};
use crate::outputs;
use crate::stdio;
use crate::store::{Entry, Input, RunResult, Store, unix_now};
use report::{Report, Timings, millis};

pub struct RunOptions {
    pub argv: Vec<OsString>,
    pub pass_env: Vec<String>,
    pub store_dir: PathBuf,
    pub shadow: bool,
    pub report: Option<PathBuf>,
    pub quiet: bool,
}

struct Execution {
    exit_code: i32,
    inputs: Vec<Input>,
    /// Paths that did not exist before the run and were written by it.
    created: BTreeSet<PathBuf>,
    /// None when the run can't be cached, for the `reasons` given.
    result: Option<RunResult>,
    reasons: Vec<String>,
    traced: bool,
    timings: Timings,
}

struct Console {
    quiet: bool,
}

impl Console {
    fn say(&self, message: impl Display) {
        if !self.quiet {
            eprintln!("xcache: {message}");
        }
    }

    fn error(&self, message: impl Display) {
        eprintln!("xcache: {message}");
    }
}

pub fn run(options: RunOptions) -> Result<i32> {
    let started = Instant::now();
    let console = Console { quiet: options.quiet };
    let report_path = options.report.as_deref();
    let invocation = Invocation::new(options.argv, std::env::current_dir()?, std::env::vars_os(), &options.pass_env);
    let fingerprint = invocation.fingerprint();
    let mut report = Report::new(fingerprint);

    let store = match Store::open(options.store_dir) {
        Ok(store) => store,
        Err(error) => {
            console.say(format!("cache directory unavailable ({error}); running without cache"));
            return execute::run_untraced(&invocation);
        }
    };
    let mut hasher = ContentHasher::load(store.stat_cache_path());
    let entries = store.entries(fingerprint).unwrap_or_else(|error| {
        console.say(format!("ignoring unreadable cache entries ({error})"));
        Vec::new()
    });
    let mut hit = entries.iter().find(|entry| first_mismatch(entry, &mut hasher).is_none());
    report.looked_up(started.elapsed());

    if let Some(entry) = hit
        && !options.shadow
    {
        match replay(entry, &store) {
            Ok(()) => {
                let _ = store.mark_used(fingerprint, entry.created_at);
                let _ = hasher.save();
                console.say(format!(
                    "hit, restored {} (the original run took {})",
                    count(entry.result.outputs.len(), "output"),
                    human_duration(Duration::from_millis(entry.duration_ms))
                ));
                report.restored(entry);
                report.write(report_path, started.elapsed())?;
                return Ok(entry.result.exit_code);
            }
            Err(error) => {
                console.say(format!("could not restore the cached result ({error:#}); running the command"));
                hit = None;
            }
        }
    }

    let execution = execute::execute(&invocation, &store, &mut hasher, &console)?;
    let duration = started.elapsed();
    report.executed(&execution, hit.is_some());

    if let Some(cached) = hit
        && let Some(exit_code) = shadow::verify(cached, &execution, &store, fingerprint, &console, &mut report)
    {
        let _ = store.mark_used(fingerprint, cached.created_at);
        let _ = hasher.save();
        report.exit_code = exit_code;
        report.write(report_path, duration)?;
        return Ok(exit_code);
    }

    match execution.result {
        Some(result) => {
            let (input_count, output_count) = (execution.inputs.len(), result.outputs.len());
            let entry = Entry::new(invocation.display_command(), millis(duration), execution.inputs, result);
            match store.record(fingerprint, entry) {
                Ok(()) if hit.is_some() => {}
                Ok(()) => console.say(format!(
                    "miss, cached {} and {}",
                    count(input_count, "input"),
                    count(output_count, "output")
                )),
                Err(error) => console.say(format!("not cached: could not write the cache entry ({error})")),
            }
        }
        None if execution.traced => console.say(format!("not cached: {}", summarize(&execution.reasons))),
        None => {}
    }
    let _ = hasher.save();
    report.write(report_path, duration)?;
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
            Some((input, current)) => {
                println!("{} changed ({:?}): was {}, now {current}", input.path.display(), input.access, input.state)
            }
        }
    }
    Ok(())
}

fn replay(entry: &Entry, store: &Store) -> Result<()> {
    let stdio = store.read_blob(entry.result.stdio).context("reading recorded output")?;
    outputs::restore(&entry.result.outputs, store)?;
    stdio::replay(&stdio).context("replaying output")?;
    Ok(())
}

/// Checks what costs no hashing first, then hashes the remaining files in parallel.
fn first_mismatch<'e>(entry: &'e Entry, hasher: &mut ContentHasher) -> Option<(&'e Input, State)> {
    let mismatch = |input: &'e Input, hasher: &mut ContentHasher| {
        let current = observe::probe(input.access, &input.path, hasher);
        (current != input.state).then_some((input, current))
    };
    let (files, others): (Vec<&Input>, Vec<&Input>) =
        entry.inputs.iter().partition(|input| matches!(input.state, State::File { .. }));
    if let Some(found) = others.into_iter().find_map(|input| mismatch(input, hasher)) {
        return Some(found);
    }
    let metadata_changed = files
        .iter()
        .filter(|input| !observe::file_metadata_matches(input.access, &input.path, &input.state))
        .find_map(|input| mismatch(input, hasher));
    if metadata_changed.is_some() {
        return metadata_changed;
    }
    hasher.prefetch(&files.iter().map(|input| input.path.as_path()).collect::<Vec<_>>());
    files.into_iter().find_map(|input| mismatch(input, hasher))
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
