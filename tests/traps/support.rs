use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

use serde_json::Value;

pub struct Workspace {
    pub dir: tempfile::TempDir,
    pub store: tempfile::TempDir,
    pub root: PathBuf,
}

pub struct Run {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
    pub report: Value,
}

impl Run {
    pub fn outcome(&self) -> &str {
        self.report["outcome"].as_str().unwrap_or("none")
    }

    pub fn reasons(&self) -> String {
        self.report["reasons"].to_string()
    }
}

impl Workspace {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        Self { dir, store: tempfile::tempdir().unwrap(), root }
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    pub fn write(&self, relative: &str, content: &str) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    pub fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.path(relative)).unwrap()
    }

    /// Dates a file in the past, for commands that compare modification times.
    pub fn set_age(&self, relative: &str, seconds_ago: u64) {
        let file = fs::File::options().write(true).open(self.path(relative)).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(seconds_ago)).unwrap();
    }

    /// `xcache` in the workspace, with the workspace's own cache.
    pub fn xcache(&self) -> Command {
        let mut xcache = Command::new(env!("CARGO_BIN_EXE_xcache"));
        xcache.current_dir(&self.root).env("XCACHE_DIR", self.store.path());
        xcache
    }

    pub fn run(&self, command: &[&str]) -> Run {
        self.run_with(command, |_| {})
    }

    pub fn sh(&self, script: &str) -> Run {
        self.run(&["sh", "-c", script])
    }

    pub fn shadow(&self, command: &[&str]) -> Run {
        self.run_with(command, |xcache| {
            xcache.arg("--shadow");
        })
    }

    pub fn run_with(&self, command: &[&str], configure: impl FnOnce(&mut Command)) -> Run {
        let report = self.dir.path().join("report.json");
        let _ = fs::remove_file(&report);
        let mut xcache = self.xcache();
        xcache.args(["run", "--report"]).arg(&report);
        configure(&mut xcache);
        xcache.arg("--").args(command);
        let output = xcache.output().unwrap();
        let report = fs::read(&report).map(|bytes| serde_json::from_slice(&bytes).unwrap()).unwrap_or(Value::Null);
        Run {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            report,
        }
    }

    pub fn explain(&self, command: &[&str]) -> String {
        let output = self.xcache().arg("explain").arg("--").args(command).output().unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    pub fn compile(&self, tool: &[&str], source_name: &str, source: &str, binary: &str) -> PathBuf {
        let source_path = self.path(source_name);
        fs::write(&source_path, source).unwrap();
        let binary = self.path(binary);
        let status = Command::new(tool[0])
            .args(&tool[1..])
            .arg(&binary)
            .arg(&source_path)
            .current_dir(&self.root)
            .env("CGO_ENABLED", "0")
            .env("GOCACHE", self.dir.path().join("gocache"))
            .status()
            .unwrap_or_else(|error| panic!("{} is required for this test: {error}", tool[0]));
        assert!(status.success(), "compiling {source_name} failed");
        binary
    }
}

pub fn assert_outcome(run: &Run, expected: &str) {
    assert_eq!(run.outcome(), expected, "stderr: {}\nreport: {}", run.stderr, run.report);
}
