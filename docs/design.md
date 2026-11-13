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

## Code map

| File in `src/` | What it does |
|---|---|
| `main.rs`, `lib.rs` | Entry point; the library only exposes `cli` |
| `cli.rs` | Command line and exit statuses |
| `run/` | The `run` and `explain` commands: lookup and restore (`mod.rs`), running a miss (`execute.rs`), shadow mode (`shadow.rs`) and the `--report` JSON (`report.rs`) |
| `invocation.rs` | The fingerprint of a command line, working directory and environment |
| `trace/` | The tracer: starting the command (`spawn.rs`), the seccomp filter (`filter.rs`), decoding system calls (`syscalls.rs`), the calls that only read and the supervisor thread that records them (`supervise.rs`, `notify.rs`), the calls that stop in ptrace (`handle.rs`), signals (`signals.rs`), reading the tracee's memory (`tracee.rs`), working directories (`directories.rs`) and checking sockets (`net.rs`) |
| `record.rs` | Turning system calls into inputs and outputs |
| `observe.rs` | Kinds of access, the state each records, and probing a path's current state |
| `git.rs` | Digests of git's index and reflogs |
| `outputs.rs` | Capturing outputs after a run and restoring them on a hit |
| `stdio.rs` | Forwarding, recording and replaying stdout and stderr |
| `store.rs` | The cache directory and the entries in it |
| `digest.rs` | Content digests and the stat cache |
| `path_serde.rs` | Paths that are not UTF-8 in JSON |
| `sync.rs` | Running work on all CPUs |

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
`/proc/self/cwd/x` refers to the traced process and not to xcache. So do
`/dev/fd`, `/dev/stdin`, `/dev/stdout` and `/dev/stderr`, which are symlinks
into `/proc/self`. xcache follows no other link into `/proc/self`, where it
would find its own descriptors, and does not cache a command that reaches it
through one.

### Deferred hashing

Hashing each file when it is opened would stall the command. Instead, a read
or `stat` of a file records its device, inode, size, mtime and ctime, and the
content is hashed without the command waiting for it: by threads at the lowest
priority while the command runs, and on all CPUs for whatever is left when it
exits (`digest.rs`). A digest counts only if the file still has the recorded
device, inode, size and times when the command has exited. If those have
changed, another process modified the file during the run, and the result is
not stored.

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
and then links `foo.o`, the input is `foo.c` and `foo.o` is an output.
Directories the command created, and directories it renamed into place, are
owned along with everything under them.

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

`trace/spawn.rs` forks. The child:

1. connects stdin to `/dev/null`;
2. connects stdout and stderr to pipes, which xcache forwards and records;
3. closes all other inherited file descriptors;
4. sets `no_new_privs` and installs the seccomp filter, with a listener for
   user notifications if the kernel gives it one;
5. calls `PTRACE_TRACEME` and stops itself, so the parent can set ptrace
   options and copy the listener out with `pidfd_getfd`;
6. calls `execve` on each `PATH` candidate in turn. The failed attempts are
   traced, so they show up as missing paths.

The child does not allocate after the fork. The `argv` and `envp` arrays, and
both filters, are built before it.

### Seccomp filter

`trace/filter.rs` builds a classic BPF program from the rules in
`trace/syscalls.rs`:

1. System calls through a foreign ABI (`int 0x80` or x32 on x86_64) go to the
   tracer, which marks the run uncacheable.
2. `io_uring_setup`, `io_uring_enter` and `io_uring_register` fail with
   `ENOSYS`, because io_uring can read files without a system call per
   file. Most programs that get `ENOSYS` fall back to normal calls.
3. Calls that only look at the filesystem go to the supervisor: `openat`
   without write access, creation or truncation, the `stat`, `access` and
   `readlink` calls, `getdents64` and `execve`.
4. The other filesystem calls, plus `chdir`, `connect`, `sendto`, `sendmsg`,
   `accept`, `clone3`, `unshare` and the mount calls, stop in the tracer, and
   so does `clone` with namespace flags or `CLONE_UNTRACED`. x86_64 also has
   `open`, `stat` and the other calls without `at`.
5. Everything else runs without stopping.

Builds make far more calls of the first kind: in the corpus steps that were
profiled, 86% to 99% of the calls the filter catches are reads and probes.

### Handling a call

Reads and probes are seccomp user notifications (`trace/notify.rs`). A
supervisor thread receives each one, reads the path arguments with
`process_vm_readv`, one page at a time (`trace/tracee.rs`), resolves them
against the caller's working directory or descriptor while the caller waits,
records the paths, and lets the call continue (`trace/supervise.rs`). If the
caller was interrupted in the meantime the call arrives again, and what was
recorded for the first one is at worst an input the command never read.

Since Linux 6.6 the kernel can wake the supervisor on the CPU of the caller
and the caller on the CPU of the supervisor. That is what makes a notification
cheap: waking a thread on another CPU costs an interrupt, and several times
more in a virtual machine when that CPU is idle. In a loop of `stat` and
`open` calls in a 4-CPU VM, a ptrace stop takes about 30 microseconds and a
notification about 4. A caller that wakes the sleeping supervisor
brings it to its own CPU and continues there. One that arrives while the
supervisor is busy is usually on another CPU, and waking it on the
supervisor's would move it there, until a parallel build ran on one CPU. So
the supervisor remembers on which CPU it met each caller, and only wakes
those it met on its current one that way.

Every other call stops in the tracer (`trace/handle.rs`).
`PTRACE_GET_SYSCALL_INFO` gives the system call number and arguments without
reading registers, so the same code works on both architectures. These calls
stop again when they return, because the result decides what gets recorded:
writes are only recorded if they succeeded, `accept` returns the connection
whose peer has to be checked, and `clone` with `CLONE_UNTRACED` returns the
process that has to be killed at the end. An `execve` is recorded as a read of
its path when it starts, which is a missing path if it fails.

The supervisor and the tracer share the recorder. A call is recorded before it
runs in both, so a read that comes before a write in the command is recorded
before the write.

The kernel only gives a listener to a process that doesn't already run under
one, and copying it out takes `pidfd_getfd`, which came in Linux 5.6 and which
Docker's default seccomp profile refuses without `CAP_SYS_PTRACE`. xcache
tries it on one of its own descriptors before it asks for a listener
(`notify.rs`, `available`). Without one, or with `--tracer ptrace`, the reads
and probes stop in the tracer too, and record the same inputs.

The kernel does not show the memory of a process that made itself undumpable
(`prctl(PR_SET_DUMPABLE, 0)`), to its tracer either. The paths in that
process's calls can't be read, so nothing it looked at is recorded, and the
result is not stored (`tracee.rs`, `memory_was_hidden`).

Like ptrace, the supervisor reads arguments the caller's other threads could
still change before the kernel reads them again. The tracer records what a
program shows it; it is not a sandbox.

Most of what a stop costs beyond the wake-ups was the tracer looking things
up, so it remembers what does not change between calls:

- A process's working directory is read from `/proc` once, and again after a
  `chdir`, an `fchdir`, or a rename of a directory (`trace/directories.rs`).
- A directory's real path is resolved once, until the command removes or
  replaces a directory or a symlink (`record.rs`, `real_dir`). Only
  directories are remembered, because replacing a file with a symlink is
  neither.
- One `lstat` of a path serves the checks for ownership, for links into
  `/proc`, and for the state that is recorded.

### Signals

A signal can interrupt a call while it waits for the supervisor. If the
handler was installed without `SA_RESTART`, as dash installs its `SIGCHLD`
handler, the call would fail with `EINTR`, which a `stat` or an `open` of a
local file never does otherwise. The kernel defers signals once the
supervisor has received a call (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`,
Linux 5.19), but not before.

The tracer covers the rest, because every signal stops in ptrace before its
handler runs (`trace/signals.rs`). If the thread is about to restart a call
the supervisor sees, the signal interrupted it before it ran: the result still
reads `-ERESTARTSYS` on x86_64, and on aarch64 the kernel has already moved
the program counter back to the `svc`. The tracer then holds the signal back,
lets the call run again, and sends the signal anew once the call has
returned, restoring its original `siginfo` when it is delivered. Opening a
FIFO or a device can block in the call itself, where a signal has to
interrupt it, so those are left alone.

### Processes

New processes and threads are traced automatically. The seccomp filter, and
with it the listener, is inherited across `fork` and kept across `execve`, so
notifications come from every process of the command. When the
root process exits, any traced process still running is killed and the result
is not stored; this includes processes whose fork event was still queued. If a
process dies in the middle of a write, the write is recorded anyway, and
capturing the outputs shows what actually happened.

### Network

`trace/net.rs` checks the destination of `connect`, `sendto` and `sendmsg`:

- a non-loopback address makes the run uncacheable;
- a loopback port or Unix socket is allowed only if the socket on the other
  end belongs to a traced process. The tracer notes the loopback ports the
  command binds and asks the kernel about a copy of the socket
  (`pidfd_getfd`); what that doesn't answer is looked up in
  `/proc/<pid>/net/*` and the processes' file descriptors;
- a connection that reaches nothing is an input instead: a socket path with
  no file is a missing path, and a refused loopback port, or a datagram socket
  connected to a port nothing is bound to, is a `listen` input. glibc's
  getaddrinfo connects datagram sockets, without sending, to sort the
  addresses it returns, and checks for `nscd`'s socket on every lookup;
- netlink sockets, which only talk to the kernel, are allowed.

An accepted TCP connection gets the same check from the other side.

## Shadow mode

`--shadow` runs the command on a hit, records it, and compares the two
results (`run/shadow.rs`). When they differ, or the fresh run can't be
cached, the verdict depends on the inputs: `nondeterministic` if the fresh run read the same inputs with the
same states as the cached run, `false_hit` if it read something the cached run
didn't. Paths that didn't exist are left out of this comparison, because
programs pick random names for temporary files.

Leaving the cached result in place after a `nondeterministic` verdict keeps
the commands that follow on the inputs a hit would give them. Otherwise they
would miss under `--shadow` where they hit without it, and their hits would
never be checked. Files only the fresh run created are removed, but a file it
changed that the cached run left alone keeps the change, since its earlier
content was not stored.

## Store

```
$XCACHE_DIR/
  ac/<fingerprint>.zst     entries for one invocation, zstd-compressed JSON
  cas/<2 hex>/<62 hex>     file contents and recorded output, zstd
  stat-cache/<boot id>     known digests by inode, for the current boot
  tmp/                     blobs being written
  lock                     flock taken for entry updates and gc
```

Entries carry the version of their format (`FORMAT` in `store.rs`), and
lookups ignore entries of any other version. A change to what an entry, an
input state, an output or the recorded stdout and stderr mean needs a new
version, or lookups would read old entries by new rules. The fingerprint
(`invocation.rs`) and the stat cache (`digest.rs`) have versions of their own.

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

## Open problems

- Overhead. A read or probe is a round trip to the supervisor, which is one
  thread: callers on other CPUs wait for it and are woken across CPUs. Writes,
  new processes, `execve` and signals still stop in ptrace. In a 4-CPU aarch64
  VM the median miss overhead of eight corpus projects, from fresh checkouts,
  went from +48% to +14% with the supervisor, the remembered lookups, early
  hashing and parallel storing together: none that could be measured for
  anyhow and commander, +10% to +15% for click, testify and koa, +27% for
  uuid, +39% for markupsafe and +79% for zlib. On GitHub's runners the median
  of the 29 corpus projects went from +21% to +12%
  ([run](https://github.com/salman-frs/xcache/actions/runs/43434180556)).

  Steps that are mostly path lookups stay expensive. In zlib's test step the
  supervisor spends about 5 microseconds on each of 72,000 notifications,
  three quarters of it in the kernel: two `ioctl` calls, a `poll` and a
  `process_vm_readv`. 87% of them repeat a call, flags and absolute path from
  earlier in the run, which the recorder ignores. Dropping the repeats in the
  kernel with eBPF was evaluated and not built:

  - It does not reach +10%. With no read or probe stopped at all, zlib's
    configure step still costs about +50% over a plain run, its test step
    +39% to +66%, and `uv build` +23% to +35%.
  - Seccomp decides before any eBPF program sees a call (`syscall_trace_enter`
    in `kernel/entry/common.c` and `arch/arm64/kernel/ptrace.c`, Linux 6.8),
    and its filters are classic BPF, without maps. Repeats can only run
    unstopped if the filter lets every lookup through and an eBPF program
    stops the new ones. A program that is not attached then means unrecorded
    inputs, not a slower run.
  - Only the absolute path is a safe key. The identity of a working directory
    is not: the command can move a directory it created, and the same
    relative path from it then names another file.

  What remains is ptrace. In those zlib steps, a call that changes the
  filesystem costs about 50 microseconds of wall time when it starts, of which
  the tracer works for 17; together that is 27 to 30 points. Its second stop
  costs little and is needed, because only a change that succeeded makes the
  path the command's own. Forks, `execve`, exits and signals alone cost +10%
  to +13%, so these steps cannot get under +10% while every process is traced
  with ptrace. Having the tracer wait actively instead of sleeping cut a
  ptrace stop from 30 to 9 microseconds in a loop of calls and changed nothing
  in these steps, where the other CPUs are busy anyway; polling for the next
  stop for up to 100 microseconds did not either.

  An earlier supervisor that always woke callers on its own CPU was no faster
  than ptrace on GitHub's runners (+26.5% against +26.0% median in an
  [A/B benchmark](https://github.com/salman-frs/xcache/actions/runs/43042700975)),
  because parallel steps ended up on one CPU.
- The clock and randomness can't be observed without kernel changes. Shadow
  mode shows how much they matter for a project but doesn't fix them.
