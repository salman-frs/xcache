use std::collections::{BTreeSet, HashMap};
use std::ffi::CString;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::observe;
use crate::record::Recording;
use crate::store::{Output, OutputState, Store, unique_name};

pub fn capture(recording: &Recording, store: &Store) -> Result<Vec<Output>> {
    let mut paths: BTreeSet<PathBuf> = recording.outputs.clone();
    for tree in &recording.output_trees {
        collect_tree(tree, &mut paths).with_context(|| format!("walking {}", tree.display()))?;
    }

    let end_of_run = SystemTime::now();
    let mut first_name_of_inode: HashMap<(u64, u64), PathBuf> = HashMap::new();
    let mut outputs = Vec::with_capacity(paths.len());
    for path in paths {
        let meta = fs::symlink_metadata(&path);
        let age_ns = meta
            .as_ref()
            .ok()
            .and_then(|meta| end_of_run.duration_since(meta.modified().ok()?).ok())
            .map_or(0, |age| age.as_nanos() as u64);
        let chosen_mtime_ns = match &meta {
            Ok(meta) if recording.dated_outputs.contains(&path) => {
                Some(meta.mtime() * 1_000_000_000 + meta.mtime_nsec())
            }
            _ => None,
        };
        let state = match meta {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !recording.preexisting_outputs.contains(&path) {
                    continue;
                }
                OutputState::Deleted
            }
            Err(error) => return Err(error).with_context(|| format!("inspecting output {}", path.display())),
            Ok(meta) if meta.is_symlink() => OutputState::Symlink { target: fs::read_link(&path)? },
            Ok(meta) if meta.is_dir() => OutputState::Dir { mode: observe::permission_bits(&meta) },
            Ok(meta)
                if meta.is_file()
                    && meta.nlink() > 1
                    && first_name_of_inode.contains_key(&(meta.dev(), meta.ino())) =>
            {
                OutputState::HardLink { target: first_name_of_inode[&(meta.dev(), meta.ino())].clone() }
            }
            Ok(meta) if meta.is_file() => {
                if meta.nlink() > 1 {
                    first_name_of_inode.insert((meta.dev(), meta.ino()), path.clone());
                }
                let (content, size) =
                    store.put_file(&path).with_context(|| format!("storing output {}", path.display()))?;
                OutputState::File { mode: observe::permission_bits(&meta), size, content }
            }
            Ok(meta) if meta.file_type().is_socket() => continue,
            Ok(_) => bail!("creates a FIFO or device: {}", path.display()),
        };
        outputs.push(Output { path, state, age_ns, chosen_mtime_ns });
    }
    Ok(outputs)
}

/// Restored outputs keep the order of their modification times, a microsecond
/// apart and just before the restore: newer than the work tree they are restored
/// into, as they were when the command made them, so make and cargo see them as
/// up to date.
const MODIFICATION_STEP: Duration = Duration::from_micros(1);

/// Relies on outputs being sorted by path, so parents come before their children.
pub fn restore(outputs: &[Output], store: &Store) -> Result<()> {
    let restored_at = SystemTime::now();
    for output in outputs.iter().rev() {
        if output.state == OutputState::Deleted {
            remove(&output.path).with_context(|| format!("deleting {}", output.path.display()))?;
        }
    }
    for output in outputs {
        let path = &output.path;
        match &output.state {
            OutputState::Deleted => {}
            OutputState::Dir { mode } => {
                fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
                fs::set_permissions(path, fs::Permissions::from_mode(*mode))?;
            }
            OutputState::File { mode, content, .. } => {
                write_file(path, *mode, |file| store.copy_blob_to(*content, file))
                    .with_context(|| format!("restoring {}", path.display()))?;
            }
            OutputState::HardLink { target } => {
                remove(path)?;
                fs::hard_link(target, path).with_context(|| format!("linking {}", path.display()))?;
            }
            OutputState::Symlink { target } => {
                remove(path)?;
                symlink(target, path).with_context(|| format!("linking {}", path.display()))?;
            }
        }
    }
    let restored: Vec<&Output> = outputs.iter().rev().filter(|output| output.state != OutputState::Deleted).collect();
    let mut ages: Vec<u64> = restored.iter().map(|output| output.age_ns).collect();
    ages.sort_unstable_by(|a, b| b.cmp(a));
    ages.dedup();
    for output in restored {
        let newer_ages = ages.partition_point(|&age| age > output.age_ns);
        let modified = match output.chosen_mtime_ns {
            Some(nanoseconds) => since_epoch(nanoseconds),
            None => restored_at - MODIFICATION_STEP * (ages.len() - newer_ages) as u32,
        };
        set_modified(&output.path, modified).with_context(|| format!("dating {}", output.path.display()))?;
    }
    Ok(())
}

fn since_epoch(nanoseconds: i64) -> SystemTime {
    let offset = Duration::from_nanos(nanoseconds.unsigned_abs());
    if nanoseconds >= 0 { UNIX_EPOCH + offset } else { UNIX_EPOCH - offset }
}

/// Sets the modification time without following a symlink.
fn set_modified(path: &Path, modified: SystemTime) -> io::Result<()> {
    let since_epoch = modified.duration_since(UNIX_EPOCH).unwrap_or_default();
    let times = [
        libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT },
        libc::timespec { tv_sec: since_epoch.as_secs() as libc::time_t, tv_nsec: since_epoch.subsec_nanos().into() },
    ];
    let path = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: path is NUL-terminated and times has the two entries utimensat reads.
    if unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Removes paths a run created, children before their parents.
pub fn remove_created<'p>(paths: impl Iterator<Item = &'p PathBuf>) -> Result<()> {
    for path in paths {
        let removed = match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
            Ok(_) => fs::remove_file(path),
            Err(error) => Err(error),
        };
        match removed {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                return Err(error).with_context(|| format!("removing {}", path.display()));
            }
            _ => {}
        }
    }
    Ok(())
}

fn collect_tree(root: &Path, paths: &mut BTreeSet<PathBuf>) -> io::Result<()> {
    let meta = match fs::symlink_metadata(root) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    paths.insert(root.to_path_buf());
    if meta.is_dir() {
        for entry in fs::read_dir(root)? {
            collect_tree(&entry?.path(), paths)?;
        }
    }
    Ok(())
}

fn remove(path: &Path) -> io::Result<()> {
    let result = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir(path),
        Ok(_) => fs::remove_file(path),
        Err(error) => Err(error),
    };
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn write_file(path: &Path, mode: u32, fill: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("/"));
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".{}", unique_name()));
    let result = File::create(&tmp).and_then(|mut file| {
        fill(&mut file)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, path)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::ContentHasher;
    use crate::record::{Effect, Recorder};

    #[test]
    fn captured_outputs_restore_the_same_tree() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().to_path_buf()).unwrap();
        let work = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(work.path()).unwrap();
        let stale = root.join("stale");
        fs::write(&stale, b"old").unwrap();

        let mut hasher = ContentHasher::in_memory();
        let mut recorder = Recorder::new(&mut hasher, &[]);
        let mutations = [
            (root.join("dir"), Effect::MakeNode),
            (root.join("dir/file"), Effect::Create),
            (root.join("link"), Effect::MakeLink),
            (stale.clone(), Effect::Remove),
        ];
        for (path, effect) in mutations {
            let mutation = recorder.before_mutation(&path, effect).unwrap();
            match effect {
                Effect::MakeNode => fs::create_dir(&path).unwrap(),
                Effect::Create => fs::write(&path, b"content").unwrap(),
                Effect::MakeLink => symlink("dir/file", &path).unwrap(),
                _ => fs::remove_file(&path).unwrap(),
            }
            recorder.mutated(mutation);
        }
        let outputs = capture(&recorder.finish(), &store).unwrap();

        fs::remove_dir_all(root.join("dir")).unwrap();
        fs::remove_file(root.join("link")).unwrap();
        fs::write(&stale, b"old").unwrap();
        restore(&outputs, &store).unwrap();

        assert_eq!(fs::read(root.join("link")).unwrap(), b"content");
        assert!(!stale.exists());
    }

    #[test]
    fn hard_links_between_outputs_are_restored_as_links() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().to_path_buf()).unwrap();
        let work = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(work.path()).unwrap();
        let (binary, alias) = (root.join("tool-1234"), root.join("tool"));

        let mut hasher = ContentHasher::in_memory();
        let mut recorder = Recorder::new(&mut hasher, &[]);
        let created = recorder.before_mutation(&binary, Effect::Create).unwrap();
        fs::write(&binary, b"binary").unwrap();
        recorder.mutated(created);
        let linked = recorder.before_mutation(&alias, Effect::MakeLink).unwrap();
        fs::hard_link(&binary, &alias).unwrap();
        recorder.mutated(linked);
        let outputs = capture(&recorder.finish(), &store).unwrap();
        fs::remove_file(&binary).unwrap();
        fs::remove_file(&alias).unwrap();
        restore(&outputs, &store).unwrap();

        let inode = |path: &Path| fs::metadata(path).unwrap().ino();
        assert_eq!(inode(&binary), inode(&alias));
        assert_eq!(fs::read(&binary).unwrap(), b"binary");
    }

    #[test]
    fn restoring_keeps_the_order_of_modification_times() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().to_path_buf()).unwrap();
        let work = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(work.path()).unwrap();
        let (older, newer) = (root.join("z-older"), root.join("a-newer"));

        let mut hasher = ContentHasher::in_memory();
        let mut recorder = Recorder::new(&mut hasher, &[]);
        for path in [&older, &newer] {
            let mutation = recorder.before_mutation(path, Effect::Create).unwrap();
            fs::write(path, b"x").unwrap();
            recorder.mutated(mutation);
            std::thread::sleep(Duration::from_millis(20));
        }
        let outputs = capture(&recorder.finish(), &store).unwrap();
        fs::remove_file(&older).unwrap();
        fs::remove_file(&newer).unwrap();
        restore(&outputs, &store).unwrap();

        let modified = |path: &Path| fs::metadata(path).unwrap().modified().unwrap();
        assert!(modified(&older) < modified(&newer));
        let restore_started = SystemTime::now() - Duration::from_millis(10);
        assert!(modified(&older) > restore_started, "restored outputs must be newer than the work tree");
    }

    #[test]
    fn temporary_files_created_and_removed_are_not_outputs() {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Store::open(store_dir.path().to_path_buf()).unwrap();
        let work = tempfile::tempdir().unwrap();
        let temporary = fs::canonicalize(work.path()).unwrap().join("tmp123");

        let mut hasher = ContentHasher::in_memory();
        let mut recorder = Recorder::new(&mut hasher, &[]);
        let created = recorder.before_mutation(&temporary, Effect::CreateExclusive).unwrap();
        fs::write(&temporary, b"scratch").unwrap();
        recorder.mutated(created);
        let removed = recorder.before_mutation(&temporary, Effect::Remove).unwrap();
        fs::remove_file(&temporary).unwrap();
        recorder.mutated(removed);

        assert!(capture(&recorder.finish(), &store).unwrap().is_empty());
    }
}
