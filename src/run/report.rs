use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use super::Execution;
use super::shadow::{Comparison, Verdict};
use crate::digest::Digest;
use crate::store::Entry;

/// What `--report` writes. corpus/corpus.py reads it, so keep the two in step.
#[derive(Serialize, Default)]
pub struct Report {
    outcome: Outcome,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<String>,
    fingerprint: String,
    pub exit_code: i32,
    inputs: usize,
    outputs: usize,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow: Option<Verdict>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    differences: Vec<String>,
    timings_ms: Timings,
}

#[derive(Serialize, Default, Clone, Copy)]
pub struct Timings {
    pub lookup: u64,
    pub command: u64,
    pub hashing: u64,
    pub store: u64,
}

#[derive(Serialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    #[default]
    Miss,
    Hit,
    NotCached,
    Untraced,
}

impl Report {
    pub fn new(fingerprint: Digest) -> Self {
        Self { fingerprint: fingerprint.to_hex(), ..Self::default() }
    }

    pub fn looked_up(&mut self, lookup_time: Duration) {
        self.timings_ms.lookup = millis(lookup_time);
    }

    pub fn restored(&mut self, entry: &Entry) {
        self.outcome = Outcome::Hit;
        self.exit_code = entry.result.exit_code;
        self.inputs = entry.inputs.len();
        self.outputs = entry.result.outputs.len();
    }

    /// `shadowing_a_hit` reports a hit that `--shadow` ran anyway as a hit.
    pub fn executed(&mut self, execution: &Execution, shadowing_a_hit: bool) {
        self.timings_ms = Timings { lookup: self.timings_ms.lookup, ..execution.timings };
        self.exit_code = execution.exit_code;
        self.inputs = execution.inputs.len();
        self.outputs = execution.result.as_ref().map_or(0, |result| result.outputs.len());
        self.reasons = execution.reasons.clone();
        self.outcome = match (&execution.result, execution.traced) {
            _ if shadowing_a_hit => Outcome::Hit,
            (_, false) => Outcome::Untraced,
            (Some(_), true) => Outcome::Miss,
            (None, true) => Outcome::NotCached,
        };
    }

    pub fn compared(&mut self, comparison: &Comparison) {
        self.shadow = Some(comparison.verdict);
        self.differences = comparison.differences.clone();
    }

    pub fn write(&mut self, path: Option<&Path>, duration: Duration) -> Result<()> {
        let Some(path) = path else {
            return Ok(());
        };
        self.duration_ms = millis(duration);
        let json = serde_json::to_vec_pretty(self)?;
        fs::write(path, json).with_context(|| format!("writing report {}", path.display()))
    }
}

pub fn millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}
