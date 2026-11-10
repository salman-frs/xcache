use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::digest::Digest;

const FORMAT: &[u8] = b"xcache-invocation-v1";

// Values that differ on every CI run or login session. They are removed from
// the command's environment, so the command provably cannot depend on them.
const VOLATILE_VARS: &[&str] = &[
    "GITHUB_ACTION",
    "GITHUB_ACTION_PATH",
    "GITHUB_ACTION_REF",
    "GITHUB_ACTION_REPOSITORY",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_BASE_REF",
    "GITHUB_ENV",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_HEAD_REF",
    "GITHUB_OUTPUT",
    "GITHUB_PATH",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_PROTECTED",
    "GITHUB_REF_TYPE",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_SHA",
    "GITHUB_STATE",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_TOKEN",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "HOSTNAME",
    "INVOCATION_ID",
    "JOURNAL_STREAM",
    "OLDPWD",
    "PWD",
    "RUNNER_NAME",
    "RUNNER_TRACKING_ID",
    "SHLVL",
    "SSH_AUTH_SOCK",
    "SSH_CLIENT",
    "SSH_CONNECTION",
    "SSH_TTY",
    "TERM_SESSION_ID",
    "WINDOWID",
    "XDG_SESSION_ID",
    "_",
];
const VOLATILE_PREFIXES: &[&str] = &["ACTIONS_", "XCACHE_"];

pub struct Invocation {
    pub argv: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: Vec<(OsString, OsString)>,
}

impl Invocation {
    pub fn new(
        argv: Vec<OsString>,
        cwd: PathBuf,
        ambient_env: impl IntoIterator<Item = (OsString, OsString)>,
        pass_env: &[String],
    ) -> Self {
        Self { argv, cwd, env: hermetic_env(ambient_env, pass_env) }
    }

    pub fn fingerprint(&self) -> Digest {
        let mut hasher = blake3::Hasher::new();
        let mut field = |bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        field(FORMAT);
        field(std::env::consts::ARCH.as_bytes());
        let (uid, gid, umask) = identity();
        field(&uid.to_le_bytes());
        field(&gid.to_le_bytes());
        field(&umask.to_le_bytes());
        field(self.cwd.as_os_str().as_bytes());
        field(&(self.argv.len() as u64).to_le_bytes());
        for arg in &self.argv {
            field(arg.as_bytes());
        }
        for (name, value) in &self.env {
            field(name.as_bytes());
            field(value.as_bytes());
        }
        Digest::of_hasher(&hasher)
    }

    pub fn display_command(&self) -> String {
        self.argv.iter().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>().join(" ")
    }

    pub fn path_var(&self) -> Option<&OsStr> {
        self.env.iter().find(|(name, _)| name == "PATH").map(|(_, value)| value.as_os_str())
    }
}

fn hermetic_env(
    ambient_env: impl IntoIterator<Item = (OsString, OsString)>,
    pass_env: &[String],
) -> Vec<(OsString, OsString)> {
    let mut env: Vec<_> = ambient_env
        .into_iter()
        .filter(|(name, _)| pass_env.iter().any(|passed| name == passed.as_str()) || !is_volatile(name))
        .collect();
    env.sort();
    env
}

fn is_volatile(name: &OsStr) -> bool {
    let name = name.as_bytes();
    VOLATILE_VARS.iter().any(|volatile| name == volatile.as_bytes())
        || VOLATILE_PREFIXES.iter().any(|prefix| name.starts_with(prefix.as_bytes()))
}

fn identity() -> (u32, u32, u32) {
    // SAFETY: getuid/getgid cannot fail; umask is read by setting and restoring
    // it while xcache is still single-threaded.
    unsafe {
        let umask = libc::umask(0o022);
        libc::umask(umask);
        (libc::getuid(), libc::getgid(), umask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs.iter().map(|(name, value)| (name.into(), value.into())).collect()
    }

    #[test]
    fn volatile_variables_are_removed_unless_passed() {
        let ambient = vars(&[("GITHUB_SHA", "abc"), ("ACTIONS_RUNTIME_TOKEN", "t"), ("CC", "gcc")]);
        let invocation = Invocation::new(vec![], "/".into(), ambient.clone(), &[]);
        assert_eq!(invocation.env, vars(&[("CC", "gcc")]));

        let passed = Invocation::new(vec![], "/".into(), ambient, &["GITHUB_SHA".into()]);
        assert_eq!(passed.env, vars(&[("CC", "gcc"), ("GITHUB_SHA", "abc")]));
    }

    #[test]
    fn fingerprint_depends_on_argv_cwd_and_env() {
        let base = || Invocation::new(vec!["make".into()], "/src".into(), vars(&[("A", "1")]), &[]);
        let other_arg = Invocation::new(vec!["make".into(), "-j".into()], "/src".into(), vars(&[("A", "1")]), &[]);
        let other_cwd = Invocation::new(vec!["make".into()], "/other".into(), vars(&[("A", "1")]), &[]);
        let other_env = Invocation::new(vec!["make".into()], "/src".into(), vars(&[("A", "2")]), &[]);
        let volatile =
            Invocation::new(vec!["make".into()], "/src".into(), vars(&[("A", "1"), ("GITHUB_SHA", "x")]), &[]);

        assert_eq!(base().fingerprint(), base().fingerprint());
        assert_ne!(base().fingerprint(), other_arg.fingerprint());
        assert_ne!(base().fingerprint(), other_cwd.fingerprint());
        assert_ne!(base().fingerprint(), other_env.fingerprint());
        assert_eq!(base().fingerprint(), volatile.fingerprint());
    }

    #[test]
    fn argument_boundaries_are_part_of_the_fingerprint() {
        let split = Invocation::new(vec!["a".into(), "b".into()], "/".into(), vec![], &[]);
        let joined = Invocation::new(vec!["ab".into()], "/".into(), vec![], &[]);
        assert_ne!(split.fingerprint(), joined.fingerprint());
    }
}
