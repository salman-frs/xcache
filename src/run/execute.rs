use std::collections::BTreeSet;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result};

use super::report::{Timings, millis};
use super::{Console, Execution};
use crate::digest::ContentHasher;
use crate::invocation::Invocation;
use crate::outputs;
use crate::record::Recorder;
use crate::store::{RunResult, Store};
use crate::trace::{self, Exit, Outcome, Tracing};

/// Runs the command under the tracer and captures its outputs if it can be cached.
pub fn execute(
    invocation: &Invocation,
    store: &Store,
    hasher: &mut ContentHasher,
    tracing: Tracing,
    console: &Console,
) -> Result<Execution> {
    let store_root = fs::canonicalize(store.root()).unwrap_or_else(|_| store.root().to_path_buf());
    let recorder = Recorder::new(hasher, &[store_root.as_path()]);
    match trace::run(invocation, recorder, tracing)? {
        Outcome::Unavailable { reason } => {
            console.error(format!("tracing is unavailable ({reason}); running without cache"));
            let exit_code = run_untraced(invocation)?;
            Ok(Execution {
                exit_code,
                inputs: Vec::new(),
                created: BTreeSet::new(),
                result: None,
                reasons: vec![reason],
                traced: false,
                timings: Timings::default(),
            })
        }
        Outcome::ExecFailed { errno } => {
            let program = invocation.argv[0].to_string_lossy();
            let error = std::io::Error::from_raw_os_error(errno);
            console.error(format!("{program}: {error}"));
            let exit_code = if errno == libc::ENOENT { 127 } else { 126 };
            Ok(Execution {
                exit_code,
                inputs: Vec::new(),
                created: BTreeSet::new(),
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
                command: millis(traced.command_time),
                hashing: millis(traced.hashing_time),
                store: millis(storing.elapsed()),
            };
            let created = traced.recording.outputs.difference(&traced.recording.preexisting_outputs).cloned().collect();
            Ok(Execution {
                exit_code: traced.exit.code(),
                inputs: traced.recording.inputs,
                created,
                result,
                reasons,
                traced: true,
                timings,
            })
        }
    }
}

pub fn run_untraced(invocation: &Invocation) -> Result<i32> {
    let status = Command::new(&invocation.argv[0])
        .args(&invocation.argv[1..])
        .env_clear()
        .envs(invocation.env.iter().map(|(name, value)| (name, value)))
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("running {}", invocation.argv[0].to_string_lossy()))?;
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}
