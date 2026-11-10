use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::observe;
use crate::record::Recording;
use crate::store::{Output, OutputState, Store, unique_name};

pub fn capture(recording: &Recording, store: &Store) -> Result<Vec<Output>> {
    let mut paths: BTreeSet<PathBuf> = recording.outputs.clone();
    for tree in &recording.output_trees {
        collect_tree(tree, &mut paths).with_context(|| format!("walking {}", tree.display()))?;
    }

    let mut outputs = Vec::with_capacity(paths.len());
    for path in paths {
        if path.to_str().is_none() {
            bail!("writes a path that is not valid UTF-8: {}", path.display());
        }
        let state = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !recording.preexisting_outputs.contains(&path) {
                    continue;
                }
                OutputState::Deleted
            }
            Err(error) => return Err(error).with_context(|| format!("inspecting output {}", path.display())),
            Ok(meta) if meta.is_symlink() => OutputState::Symlink { target: fs::read_link(&path)? },
            Ok(meta) if meta.is_dir() => OutputState::Dir { mode: observe::permission_bits(&meta) },
            Ok(meta) if meta.is_file() => {
                let (content, size) =
                    store.put_file(&path).with_context(|| format!("storing output {}", path.display()))?;
                OutputState::File { mode: observe::permission_bits(&meta), size, content }
            }
            Ok(_) => bail!("creates a FIFO, socket or device: {}", path.display()),
        };
        outputs.push(Output { path, state });
    }
    Ok(outputs)
}

/// Relies on outputs being sorted by path, so parents come before their children.
pub fn restore(outputs: &[Output], store: &Store) -> Result<()> {
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
            OutputState::Symlink { target } => {
                remove(path)?;
                symlink(target, path).with_context(|| format!("linking {}", path.display()))?;
            }
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
