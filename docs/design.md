# Design

This describes how xcache decides that a cached result can be reused, and the
code that implements it. File names refer to `src/`.

## Overview

xcache treats a command as a function of two things:

- the invocation: arguments, working directory, environment, uid, gid, umask
  and CPU architecture;
- the state of every path the command looked at while it ran.

The result is the final state of every path it changed, plus stdout, stderr
and the exit status.

A process can only learn about the filesystem through system calls, so tracing
those calls gives the complete list of paths the command looked at. The inputs
that don't go through a system call are the clock, randomness, and whatever
the command reads under `/proc`, `/sys` and `/dev`. xcache doesn't track those.

## Lookup

The invocation is hashed into a fingerprint (`invocation.rs`). Each field is
length-prefixed, so `a b` and `ab` hash differently. The fingerprint names a
file with up to 16 entries, newest first. An entry is one recorded run: the
inputs it depended on, the state of each, and the result.

A single hash is not enough, because the set of inputs is only known after the
command has run and can change from one run to the next. Lookup goes through
the entries in order, evaluates each recorded input against the filesystem,
and stops at the first mismatch. The first entry with no mismatch is a hit.
`xcache explain` prints the first mismatch of each entry. BuildXL calls this a
two-phase lookup; ccache does the same thing with its manifests.

Variables that change on every CI run (`GITHUB_SHA`, tokens, `PWD` and others)
are removed from the command's environment rather than just left out of the
fingerprint. Leaving them out of the fingerprint while still passing them on
would let a command embed `GITHUB_SHA` in its output and get a stale hit.
`--pass-env` puts a variable back and makes it part of the fingerprint.

## Inputs

An input is a path plus the kind of access, and each kind records only what
the corresponding system calls can tell the command (`observe.rs`):

| Access | Comes from | Recorded state |
|---|---|---|
| `read` | `open` for reading, `execve`, files mapped by `execve` | content (BLAKE3), size, permission bits |
| `stat` | `stat`, `statx`, `access`, `chdir`, `open(O_PATH)` | type, permission bits; size and content for a file |
| `lstat` | `lstat`, `readlink`, `AT_SYMLINK_NOFOLLOW`, `O_NOFOLLOW` | as `stat`, or the target of a symlink |
| `list` | `getdents64` | names and types of the entries |
| `writable` | create with truncation | whether the parent is a directory, whether the path is one |
| `listen` | a connection to a loopback port that reached nothing | whether anything is bound to the port |

A `stat` can't see a file's content, but it does see its modification time,
and make, ninja, git and Python's bytecode cache decide what to do by comparing
those times. A command that found `main.o` newer than `main.c` and did nothing
would otherwise hit after `main.c` was edited to different content of the same
size. Times change on every checkout, so they can't be part of the key. A file's
content is recorded instead: when it is unchanged, so is anything the command
could have derived from its time, as long as the command is deterministic.

Git's bookkeeping needs a closer look. The index (`.git/index`) keeps the
inode, times and size of every tracked file, and the reflogs (`.git/logs/`)
record who moved HEAD and when, with an identity that names the machine when no
user is configured. Two checkouts of the same commit differ in both, and cargo
and `go build` read them on every build. The index digest covers the paths,
modes, object IDs and flags of its entries, and its extensions except the
offset tables that follow from the entries; a reflog digest covers each entry's
object IDs and message (`git.rs`). Git uses the entries' stat data only to skip
re-reading work tree files, and those files are inputs by content. The
untracked cache (`core.untrackedCache`) is different: git trusts its listings
while directory times match, so it stays in the digest, and checkouts that use
it miss.

A path that doesn't exist is recorded as missing. This matters for search
paths: a compiler that finds `config.h` in its fifth include directory has
also checked four places where it wasn't, and a `config.h` added to any of
them changes the result. `ENOENT` and other errors are recorded separately.

The kernel maps the ELF interpreter during `execve` without a system call
that the tracer sees, so after each `execve` xcache reads `/proc/<pid>/maps`
and records every mapped file as read.

Paths are recorded the way the command wrote them, joined to its working
directory or directory file descriptor. If a symlink in the path later points
somewhere else, evaluating the same path follows the new target and the
lookup sees the change. Paths under `/proc` are resolved first, because
`/proc/self/cwd/x` refers to the traced process and not to xcache.

### Deferred hashing

Hashing each file when it is opened would stall the command. Instead, a read
or `stat` of a file records its device, inode, size, mtime and ctime, and the
content is hashed after the command exits. If those have changed by then, another process
modified the file during the run, and the result is not stored.

If the command itself writes to a file it read earlier, the pending hash is
computed before the write goes through, so the recorded content is what the
command read (`record.rs`, `settle_deferred_observations_of`).

## Writes

Every write is handled when the system call starts, while the process is
stopped and the old state is still there, and again when it returns.

The first write to a path can depend on what was there before. That state is
recorded as an input:

| Write | Input recorded first |
|---|---|
| `open(O_CREAT\|O_TRUNC)`, rename onto a path | `writable` |
| `open(O_CREAT\|O_EXCL)`, `unlink`, `mkdir`, `mknod`, `symlink`, `link` target | `lstat` |
| open for writing without `O_TRUNC`, `O_RDONLY\|O_CREAT`, `truncate` to a non-zero length | `read`, hashed immediately |
| `rmdir` | `list` |
| rename source | `read` for a file, `lstat` for a symlink; a directory the command didn't create makes the run uncacheable |
| `chmod`, `fchmod`, setting a chosen time with `utimensat` | `read` |
| `truncate` to zero | `stat` |

Opening, truncating or chmodding a symlink changes the file it points to. In
that case the symlink is recorded with `lstat`, and the target is treated as
the path being written.

`link(a, b)` changes the ctime of `a`, which would look like an outside
modification, so `a` is hashed before the link is made.

### Paths the command owns

After a successful write, the path and its inode belong to the command, and
reading them later is not an input. If `make` compiles `foo.c` into `foo.o`
and then links `foo.o`, the input is `foo.c` and `foo.o` is an output. Directories the
command created, and directories it renamed into place, are owned along with
everything under them.

Ownership is checked against the path's real location: its parent directory
with symlinks and `..` resolved, plus the file name. Without that,
`mkdir build && cd build && cc ../main.c` would read `build/../main.c`, which
looks like it is inside the new `build` directory.

`chmod` on a directory doesn't make the directory owned, because its entries
are still the ones that were there before.

### Directory listings

A tool can list a directory while writing into it. A bundler that writes
`dist/` and then lists it to produce a manifest would see its own files. Those
files don't exist before the run, so recording the listing as seen would make
every lookup miss.

The listing is recorded as it was before the run: names the command created
are removed, and pre-existing names it deleted are added back.

## Outputs

When the command exits, xcache stores the final state of every path it wrote:
file content and permission bits, directories, symlinks, and deletions
(`outputs.rs`). Directories that were renamed into place are walked. Paths
that didn't exist before the run and don't exist after it are skipped, which
drops compiler temporaries with random names.

Restored files get modification times in the order the run left them, a
microsecond apart just before the restore, so build tools see them as newer
than the checkout they are restored into. A file whose time the command set to
a value from before or after the run, as `touch -d` and `cp -p` do, gets that
time back. A time within the run, like cargo dating dep-info files to the start
of the build, is about the run, and is restored in order with the rest.

Restoring removes deleted paths first, deepest first, then creates
directories, files and symlinks in path order. Files are written under a
temporary name and renamed into place. Content is checked against its digest
as it is read from the store, and if anything fails, xcache runs the command
instead.

## Tracer

### Starting the command

`trace/mod.rs` forks. The child:

1. connects stdin to `/dev/null`;
2. connects stdout and stderr to pipes, which xcache forwards and records;
3. closes all other inherited file descriptors;
4. calls `PTRACE_TRACEME` and stops itself so the parent can set ptrace
   options;
5. sets `no_new_privs` and installs the seccomp filter;
6. calls `execve` on each `PATH` candidate in turn. The failed attempts are
   traced, so they show up as missing paths.

The child does not allocate after the fork. The `argv` and `envp` arrays are
built before it.

### Seccomp filter

`trace/filter.rs` builds a classic BPF program:

1. System calls through a foreign ABI (`int 0x80` or x32 on x86_64) go to the
   tracer, which marks the run uncacheable.
2. `io_uring_setup`, `io_uring_enter` and `io_uring_register` fail with
   `ENOSYS`, because io_uring can read files without a system call per
   file. Most programs that get `ENOSYS` fall back to normal calls.
3. The filesystem calls, plus `connect`, `sendto`, `sendmsg`, `accept`,
   `clone`, `unshare` and the mount calls, stop in the tracer: 44 calls on
   aarch64 and 59 on x86_64, which still has `open`, `stat` and the other
   calls without `at`.
4. Everything else runs without stopping.

### Handling a stop

`PTRACE_GET_SYSCALL_INFO` gives the system call number and arguments without
reading registers, so the same code works on both architectures. Path
arguments are read with `process_vm_readv`, one page at a time
(`trace/tracee.rs`).

Reads and probes are recorded when the call starts, and the process continues
right away. A few calls also stop when they return, because the result decides
what gets recorded: writes are only recorded if they succeeded, a failed
`execve` is recorded as a missing path, `accept` returns the connection whose
peer has to be checked, and `clone` with `CLONE_UNTRACED` returns the process
that has to be killed at the end.

### Processes

New processes and threads are traced automatically. An `execve` from a thread
other than the leader is matched with the call that thread started. When the
root process exits, any traced process still running is killed and the result
is not stored; this includes processes whose fork event was still queued. If a
process dies in the middle of a write, the write is recorded anyway, and
capturing the outputs shows what actually happened.

### Network

`trace/net.rs` checks the destination of `connect`, `sendto` and `sendmsg`:

- a non-loopback address makes the run uncacheable;
- a loopback port or Unix socket is allowed only if the socket on the other
  end belongs to a traced process, which is checked with `/proc/<pid>/net/*`
  and the processes' file descriptors;
- a connection that reaches nothing is an input instead: a socket path with
  no file is a missing path, and a refused loopback port, or a datagram socket
  connected to a port nothing is bound to, is a `listen` input. glibc's
  getaddrinfo connects datagram sockets, without sending, to sort the
  addresses it returns, and checks for `nscd`'s socket on every lookup;
- netlink sockets, which only talk to the kernel, are allowed.

An accepted TCP connection gets the same check from the other side.

## Shadow mode

`--shadow` runs the command on a hit, records it, and compares the two
results (`run.rs`). If they differ, or the fresh run is not cacheable:

- `nondeterministic` means the fresh run read the same inputs, with the same
  states, as the cached run;
- `false_hit` means it read something the cached run didn't.

Paths that didn't exist are ignored in this comparison. Programs pick random
names for temporary files, so every run checks different missing paths.

When the result is `correct` or `nondeterministic`, xcache restores the cached
outputs and exits with the cached status, as a hit would. Otherwise every
nondeterministic command would change the inputs of the commands after it, and
those commands would miss under `--shadow` where they hit without it, so their
hits would never be checked. Files only the fresh run created are removed, but
a file it changed that the cached run left alone keeps the change, since its
earlier content was not stored. A false hit keeps the fresh result, and the
entry that produced it is removed so that later runs can't reuse it.

## Store

```
$XCACHE_DIR/
  ac/<fingerprint>.zst     entries for one invocation, zstd-compressed JSON
  cas/<2 hex>/<62 hex>     file contents and recorded output, zstd
  stat-cache/<boot id>     known digests by inode, for the current boot
  tmp/                     blobs being written
  lock                     flock taken for entry updates and gc
```

Blobs are named by the BLAKE3 digest of their uncompressed content. They are
not fsynced; every read checks the digest instead. Entry files are rewritten
under the lock and fsynced before the rename.

The stat cache lets lookups skip hashing a file whose device, inode, size,
mtime and ctime haven't changed. Like git, it ignores files modified less than
two seconds before they were hashed, since they could change again within the
same timestamp. It is kept per boot because inode numbers don't identify a
file on another machine, and CI can copy the cache directory to one.

`gc` keeps the most recently used entries that fit in the size budget, deletes
blobs that no remaining entry uses, and deletes stat caches from other boots.

## Tests

`tests/traps.rs` sets up cases where a cache that missed some input would
return the wrong result, and checks that xcache doesn't. It runs on x86_64 and
aarch64; x86_64 has the older system calls and the 32-bit ABI to cover as
well.

## Open problems

- Overhead. Every traced call is a round trip to one tracer thread, which
  costs tens of microseconds in a VM. Seccomp user notifications would allow
  several threads to answer calls and are the planned replacement.
- The clock and randomness can't be observed without kernel changes. Shadow
  mode shows how much they matter for a project but doesn't fix them.
- A shared cache needs signed entries and read-only access for untrusted
  builds before it is safe.
- macOS hosts need a different tracing mechanism.
