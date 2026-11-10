use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::digest::ContentHasher;
use crate::observe::{self, Access, EntryKind, State};
use crate::store::Input;

pub struct Recording {
    pub inputs: Vec<Input>,
    pub outputs: BTreeSet<PathBuf>,
    pub preexisting_outputs: BTreeSet<PathBuf>,
    pub output_trees: BTreeSet<PathBuf>,
    /// Outputs whose modification time the command set to a chosen value last.
    pub dated_outputs: BTreeSet<PathBuf>,
    pub taints: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Create,
    CreateExclusive,
    Modify,
    Remove,
    RemoveDir,
    RenameFrom,
    RenameTo,
    MakeNode,
    MakeLink,
    Chmod,
    SetTimes,
    TruncateToZero,
}

impl Effect {
    fn follows_symlinks(self) -> bool {
        matches!(self, Effect::Create | Effect::Modify | Effect::Chmod | Effect::SetTimes | Effect::TruncateToZero)
    }
}

pub struct Mutation {
    path: PathBuf,
    effect: Effect,
    parent: Option<PathBuf>,
    name: Option<OsString>,
    before: Option<EntryKind>,
}

enum Recorded {
    Known(State),
    /// A regular file whose content is hashed when the command finishes,
    /// provided it still has the identity it had when it was observed.
    Deferred(Identity),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Identity {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

struct Observation {
    access: Access,
    path: PathBuf,
    recorded: Recorded,
}

pub struct Recorder<'h> {
    hasher: &'h mut ContentHasher,
    excluded: Vec<PathBuf>,
    observations: Vec<Observation>,
    seen: HashMap<Access, HashSet<PathBuf>>,
    deferred_by_path: HashMap<PathBuf, Vec<usize>>,
    deferred_by_inode: HashMap<(u64, u64), Vec<usize>>,
    owned_paths: HashSet<PathBuf>,
    owned_inodes: HashSet<(u64, u64)>,
    owned_trees: Vec<PathBuf>,
    outputs: BTreeSet<PathBuf>,
    preexisting_outputs: BTreeSet<PathBuf>,
    output_trees: BTreeSet<PathBuf>,
    dated_outputs: BTreeSet<PathBuf>,
    created: HashMap<PathBuf, HashSet<OsString>>,
    removed: HashMap<PathBuf, HashMap<OsString, EntryKind>>,
    taints: Vec<String>,
}

impl<'h> Recorder<'h> {
    pub fn new(hasher: &'h mut ContentHasher, private_dirs: &[&Path]) -> Self {
        Self {
            hasher,
            excluded: private_dirs.iter().map(|dir| dir.to_path_buf()).collect(),
            observations: Vec::new(),
            seen: HashMap::new(),
            deferred_by_path: HashMap::new(),
            deferred_by_inode: HashMap::new(),
            owned_paths: HashSet::new(),
            owned_inodes: HashSet::new(),
            owned_trees: Vec::new(),
            outputs: BTreeSet::new(),
            preexisting_outputs: BTreeSet::new(),
            output_trees: BTreeSet::new(),
            dated_outputs: BTreeSet::new(),
            created: HashMap::new(),
            removed: HashMap::new(),
            taints: Vec::new(),
        }
    }

    pub fn taint(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.taints.contains(&reason) {
            self.taints.push(reason);
        }
    }

    pub fn observe(&mut self, access: Access, path: &Path) {
        self.record_observation(access, path, false);
    }

    /// Called before the kernel performs a mutation, while the command is
    /// stopped, so the pre-mutation state can still be captured.
    pub fn before_mutation(&mut self, requested: &Path, effect: Effect) -> Option<Mutation> {
        let mut path = real_location(requested);
        if effect.follows_symlinks() && fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_symlink()) {
            self.record_observation(Access::Lstat, &path, true);
            path = resolve_symlinks(&path);
        }
        let path = path.as_path();
        if self.is_excluded(path) {
            return None;
        }
        self.settle_deferred_observations_of(path);
        let before = fs::symlink_metadata(path).ok().map(|meta| EntryKind::of(meta.file_type()));

        if !self.is_owned(path) {
            let access = match (effect, before) {
                (Effect::RenameFrom, Some(EntryKind::Dir)) => {
                    self.taint(format!("renames a directory it did not create: {}", path.display()));
                    None
                }
                (Effect::RenameFrom, Some(EntryKind::File))
                | (Effect::Modify | Effect::Chmod | Effect::SetTimes, _) => Some(Access::Read),
                (Effect::Create | Effect::RenameTo, _) => Some(Access::Writable),
                (Effect::RemoveDir, _) => Some(Access::List),
                (Effect::TruncateToZero, _) => Some(Access::Stat),
                (
                    Effect::CreateExclusive | Effect::Remove | Effect::RenameFrom | Effect::MakeNode | Effect::MakeLink,
                    _,
                ) => Some(Access::Lstat),
            };
            if let Some(access) = access {
                self.record_observation(access, path, true);
            }
        }

        Some(Mutation {
            path: path.to_path_buf(),
            effect,
            parent: path.parent().map(Path::to_path_buf),
            name: path.file_name().map(OsString::from),
            before,
        })
    }

    /// Setting a file's times leaves its content alone but changes the identity
    /// that deferred hashing checks, so what was observed is hashed first.
    pub fn before_times_change(&mut self, path: &Path, follows_symlinks: bool) {
        let path = real_location(path);
        let path = if follows_symlinks { resolve_symlinks(&path) } else { path };
        self.settle_deferred_observations_of(&path);
    }

    /// Linking changes the source's ctime, so its content is captured first.
    pub fn before_link(&mut self, source: &Path) {
        self.settle_deferred_observations_of(&real_location(source));
        self.record_observation(Access::Lstat, source, true);
        self.record_observation(Access::Read, source, true);
    }

    /// Called after the kernel reported that the mutation succeeded.
    pub fn mutated(&mut self, mutation: Mutation) {
        let Mutation { path, effect, parent, name, before } = mutation;
        if effect == Effect::SetTimes {
            self.dated_outputs.insert(path.clone());
        } else {
            self.dated_outputs.remove(&path);
        }
        if self.outputs.insert(path.clone()) && before.is_some() {
            self.preexisting_outputs.insert(path.clone());
        }
        if matches!(effect, Effect::Remove | Effect::RemoveDir | Effect::RenameFrom) {
            self.owned_paths.insert(path);
            self.note_removed_entry(parent, name, before);
            return;
        }

        let meta = if effect == Effect::MakeLink { fs::symlink_metadata(&path) } else { fs::metadata(&path) };
        let is_dir = meta.as_ref().is_ok_and(fs::Metadata::is_dir);
        // A chmod leaves a directory's entries as they were, so they remain inputs.
        if !(matches!(effect, Effect::Chmod | Effect::SetTimes) && is_dir) {
            if let Ok(meta) = &meta {
                self.owned_inodes.insert((meta.dev(), meta.ino()));
            }
            if effect == Effect::MakeNode && is_dir && before.is_none() {
                self.owned_trees.push(path.clone());
            }
            self.owned_paths.insert(path);
        }
        if before.is_none() {
            self.note_created_entry(parent, name);
        }
    }

    pub fn renamed(&mut self, from: Mutation, to: Mutation) {
        let moved_directory = from.before == Some(EntryKind::Dir);
        let destination = to.path.clone();
        let dated = self.dated_outputs.contains(&from.path);
        self.mutated(from);
        self.mutated(to);
        if dated {
            self.dated_outputs.insert(destination.clone());
        }
        if moved_directory {
            self.owned_trees.push(destination.clone());
            self.output_trees.insert(destination);
        }
    }

    pub fn finish(mut self) -> Recording {
        let observations = std::mem::take(&mut self.observations);
        let deferred: Vec<&Path> = observations
            .iter()
            .filter(|observation| matches!(observation.recorded, Recorded::Deferred(_)))
            .map(|observation| observation.path.as_path())
            .collect();
        self.hasher.prefetch(&deferred);
        let mut inputs = Vec::with_capacity(observations.len());
        for Observation { access, path, recorded } in observations {
            let state = match recorded {
                Recorded::Known(state) => state,
                Recorded::Deferred(identity) => self.settle(access, &path, identity),
            };
            if access == Access::Read && matches!(state, State::Special { .. }) {
                self.taint(format!("reads from a FIFO, socket or device: {}", path.display()));
            }
            inputs.push(Input { access, path, state });
        }
        Recording {
            inputs,
            outputs: self.outputs,
            preexisting_outputs: self.preexisting_outputs,
            output_trees: self.output_trees,
            dated_outputs: self.dated_outputs,
            taints: self.taints,
        }
    }

    fn record_observation(&mut self, access: Access, requested: &Path, hash_now: bool) {
        if self.seen.get(&access).is_some_and(|paths| paths.contains(requested)) {
            return;
        }
        self.seen.entry(access).or_default().insert(requested.to_path_buf());
        if access == Access::Listen {
            let state = observe::probe(access, requested, self.hasher);
            self.observations.push(Observation {
                access,
                path: requested.to_path_buf(),
                recorded: Recorded::Known(state),
            });
            return;
        }
        let real = real_location(requested);
        if self.is_excluded(&real) || self.is_owned(&real) {
            return;
        }
        if leads_to_machine_state(access, &real) {
            for link in symlink_chain(&real) {
                self.record_observation(Access::Lstat, &link, true);
            }
            return;
        }
        // Paths under /proc name the tracee (cwd, fd links); record where they lead.
        let path = if requested.starts_with("/proc") { real.as_path() } else { requested };

        let recorded = match access {
            Access::Read | Access::Stat | Access::Lstat if !hash_now => match metadata(access, path) {
                Ok(meta) if meta.is_file() => Recorded::Deferred(Identity::of(&meta)),
                _ => Recorded::Known(observe::probe(access, path, self.hasher)),
            },
            Access::List => Recorded::Known(self.listing_before_run(path)),
            _ => Recorded::Known(observe::probe(access, path, self.hasher)),
        };

        let index = self.observations.len();
        if let Recorded::Deferred(identity) = &recorded {
            self.deferred_by_path.entry(path.to_path_buf()).or_default().push(index);
            self.deferred_by_inode.entry((identity.dev, identity.ino)).or_default().push(index);
        }
        self.observations.push(Observation { access, path: path.to_path_buf(), recorded });
    }

    fn listing_before_run(&mut self, dir: &Path) -> State {
        let Ok(mut listing) = observe::read_listing(dir) else {
            return observe::probe(Access::List, dir, self.hasher);
        };
        if let Some(created) = self.created.get(dir) {
            listing.retain(|name, _| !created.contains(name));
        }
        if let Some(removed) = self.removed.get(dir) {
            listing.extend(removed.iter().map(|(name, kind)| (name.clone(), *kind)));
        }
        observe::listing_state(dir, &listing)
    }

    fn settle_deferred_observations_of(&mut self, path: &Path) {
        let mut indexes: Vec<usize> = self.deferred_by_path.get(path).cloned().unwrap_or_default();
        for meta in [fs::metadata(path), fs::symlink_metadata(path)].into_iter().flatten() {
            if let Some(same_inode) = self.deferred_by_inode.get(&(meta.dev(), meta.ino())) {
                indexes.extend(same_inode);
            }
        }
        for index in indexes {
            if let Recorded::Deferred(identity) = self.observations[index].recorded {
                let (access, path) = (self.observations[index].access, self.observations[index].path.clone());
                let state = self.settle(access, &path, identity);
                self.observations[index].recorded = Recorded::Known(state);
            }
        }
    }

    fn settle(&mut self, access: Access, path: &Path, identity: Identity) -> State {
        let unchanged = metadata(access, path).is_ok_and(|meta| Identity::of(&meta) == identity);
        if !unchanged {
            self.taint(format!("input changed while the command ran: {}", path.display()));
        }
        observe::probe(access, path, self.hasher)
    }

    fn note_created_entry(&mut self, parent: Option<PathBuf>, name: Option<OsString>) {
        if let (Some(parent), Some(name)) = (parent, name) {
            self.created.entry(parent).or_default().insert(name);
        }
    }

    fn note_removed_entry(&mut self, parent: Option<PathBuf>, name: Option<OsString>, before: Option<EntryKind>) {
        let (Some(parent), Some(name)) = (parent, name) else {
            return;
        };
        let created_by_command = self.created.get_mut(&parent).is_some_and(|created| created.remove(&name));
        if !created_by_command && let Some(kind) = before {
            self.removed.entry(parent).or_default().insert(name, kind);
        }
    }

    fn is_excluded(&self, real: &Path) -> bool {
        is_machine_state(real) || self.excluded.iter().any(|excluded| real.starts_with(excluded))
    }

    fn is_owned(&self, real: &Path) -> bool {
        self.owned_paths.contains(real)
            || self.owned_trees.iter().any(|tree| real.starts_with(tree))
            || fs::metadata(real).is_ok_and(|meta| self.owned_inodes.contains(&(meta.dev(), meta.ino())))
    }
}

/// A symlink such as /etc/mtab can lead into /proc, which is machine state.
fn leads_to_machine_state(access: Access, real: &Path) -> bool {
    let follows_symlinks = matches!(access, Access::Read | Access::Stat);
    follows_symlinks
        && fs::symlink_metadata(real).is_ok_and(|meta| meta.is_symlink())
        && fs::canonicalize(real).is_ok_and(|target| is_machine_state(&target))
}

/// The symlinks a path goes through, up to the first target outside them.
fn symlink_chain(link: &Path) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut path = link.to_path_buf();
    while chain.len() < 40 && !is_machine_state(&path) {
        let Ok(target) = fs::read_link(&path) else {
            break;
        };
        let next = real_location(&path.parent().unwrap_or(Path::new("/")).join(target));
        chain.push(path);
        path = next;
    }
    chain
}

fn is_machine_state(real: &Path) -> bool {
    real.starts_with("/proc") || real.starts_with("/sys") || (real.starts_with("/dev") && !real.starts_with("/dev/shm"))
}

fn metadata(access: Access, path: &Path) -> std::io::Result<fs::Metadata> {
    if access == Access::Lstat { fs::symlink_metadata(path) } else { fs::metadata(path) }
}

/// Where a path really lives: its parent directory with symlinks and `..`
/// resolved, so lexical prefixes cannot alias another directory. Magic links
/// under /proc are followed through to their target.
fn real_location(path: &Path) -> PathBuf {
    if path.starts_with("/proc")
        && let Ok(real) = fs::canonicalize(path)
    {
        return real;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => {
            fs::canonicalize(parent).map_or_else(|_| path.to_path_buf(), |real| real.join(name))
        }
        _ => fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

fn resolve_symlinks(link: &Path) -> PathBuf {
    let mut path = link.to_path_buf();
    for _ in 0..40 {
        let Ok(target) = fs::read_link(&path) else {
            break;
        };
        path = real_location(&path.parent().unwrap_or(Path::new("/")).join(target));
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scenario {
        dir: tempfile::TempDir,
        hasher: ContentHasher,
    }

    impl Scenario {
        fn new() -> Self {
            Self { dir: tempfile::tempdir().unwrap(), hasher: ContentHasher::in_memory() }
        }

        fn root(&self) -> PathBuf {
            fs::canonicalize(self.dir.path()).unwrap()
        }

        fn path(&self, name: &str) -> PathBuf {
            self.root().join(name)
        }

        fn recorder(&mut self) -> Recorder<'_> {
            Recorder::new(&mut self.hasher, &[])
        }
    }

    fn create(recorder: &mut Recorder, path: &Path, content: &[u8]) {
        let mutation = recorder.before_mutation(path, Effect::Create).unwrap();
        fs::write(path, content).unwrap();
        recorder.mutated(mutation);
    }

    fn input<'a>(recording: &'a Recording, access: Access, path: &Path) -> Option<&'a State> {
        recording.inputs.iter().find(|input| input.access == access && input.path == path).map(|input| &input.state)
    }

    #[test]
    fn reading_its_own_output_is_not_an_input() {
        let mut scenario = Scenario::new();
        let out = scenario.path("out");
        let mut recorder = scenario.recorder();
        create(&mut recorder, &out, b"generated");
        recorder.observe(Access::Read, &out);
        let recording = recorder.finish();

        assert_eq!(
            input(&recording, Access::Writable, &out),
            Some(&State::Writable { parent_is_dir: true, is_dir: false })
        );
        assert!(input(&recording, Access::Read, &out).is_none());
        assert!(recording.outputs.contains(&out));
    }

    #[test]
    fn content_read_before_an_overwrite_is_the_original() {
        let mut scenario = Scenario::new();
        let file = scenario.path("file");
        fs::write(&file, b"original").unwrap();
        let expected = observe::probe(Access::Read, &file, &mut ContentHasher::in_memory());

        let mut recorder = scenario.recorder();
        recorder.observe(Access::Read, &file);
        let mutation = recorder.before_mutation(&file, Effect::Modify).unwrap();
        fs::write(&file, b"rewritten").unwrap();
        recorder.mutated(mutation);
        let recording = recorder.finish();

        assert_eq!(input(&recording, Access::Read, &file), Some(&expected));
        assert!(recording.taints.is_empty());
    }

    #[test]
    fn external_change_to_an_input_taints_the_run() {
        let mut scenario = Scenario::new();
        let file = scenario.path("file");
        fs::write(&file, b"one").unwrap();
        let mut recorder = scenario.recorder();
        recorder.observe(Access::Read, &file);
        fs::write(&file, b"changed by someone else").unwrap();
        let recording = recorder.finish();

        assert_eq!(recording.taints.len(), 1);
    }

    #[test]
    fn listings_exclude_entries_the_command_created() {
        let mut scenario = Scenario::new();
        let dir = scenario.root();
        let dir = dir.as_path();
        fs::write(dir.join("source"), b"").unwrap();
        let before_run = observe::probe(Access::List, dir, &mut ContentHasher::in_memory());

        let mut recorder = scenario.recorder();
        create(&mut recorder, &dir.join("generated"), b"");
        recorder.observe(Access::List, dir);
        let recording = recorder.finish();

        assert_eq!(input(&recording, Access::List, dir), Some(&before_run));
    }

    #[test]
    fn listings_include_entries_the_command_removed() {
        let mut scenario = Scenario::new();
        let dir = scenario.root();
        let dir = dir.as_path();
        let stale = dir.join("stale");
        fs::write(&stale, b"").unwrap();
        let before_run = observe::probe(Access::List, dir, &mut ContentHasher::in_memory());

        let mut recorder = scenario.recorder();
        let mutation = recorder.before_mutation(&stale, Effect::Remove).unwrap();
        fs::remove_file(&stale).unwrap();
        recorder.mutated(mutation);
        recorder.observe(Access::List, dir);
        let recording = recorder.finish();

        assert_eq!(input(&recording, Access::List, dir), Some(&before_run));
        assert_eq!(
            input(&recording, Access::Lstat, &stale).map(|state| matches!(state, State::File { .. })),
            Some(true)
        );
    }

    #[test]
    fn renaming_a_preexisting_directory_taints_the_run() {
        let mut scenario = Scenario::new();
        let dir = scenario.path("dir");
        fs::create_dir(&dir).unwrap();
        let mut recorder = scenario.recorder();
        recorder.before_mutation(&dir, Effect::RenameFrom);
        assert_eq!(recorder.finish().taints.len(), 1);
    }

    #[test]
    fn files_created_through_proc_are_owned() {
        let mut scenario = Scenario::new();
        let file = scenario.path("created");
        let dir = fs::File::open(scenario.root()).unwrap();
        let through_proc =
            PathBuf::from(format!("/proc/{}/fd/{}/created", std::process::id(), std::os::fd::AsRawFd::as_raw_fd(&dir)));
        let mut recorder = scenario.recorder();
        create(&mut recorder, &through_proc, b"x");
        recorder.observe(Access::Read, &file);
        assert!(input(&recorder.finish(), Access::Read, &file).is_none());
    }

    #[test]
    fn system_pseudo_filesystems_are_not_inputs() {
        let mut scenario = Scenario::new();
        let mut recorder = scenario.recorder();
        recorder.observe(Access::Read, Path::new("/proc/self/status"));
        assert!(recorder.finish().inputs.is_empty());
    }

    #[test]
    fn links_into_proc_are_recorded_but_not_followed() {
        let mut scenario = Scenario::new();
        let mtab = scenario.path("mtab");
        std::os::unix::fs::symlink("/proc/self/mounts", &mtab).unwrap();
        let mut recorder = scenario.recorder();
        recorder.observe(Access::Read, &mtab);
        let recording = recorder.finish();
        assert_eq!(recording.inputs.len(), 1);
        assert_eq!(recording.inputs[0].access, Access::Lstat);
        assert_eq!(recording.inputs[0].state, State::Symlink { target: "/proc/self/mounts".into() });
    }
}
