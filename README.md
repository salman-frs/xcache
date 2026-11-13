# xcache

xcache is a cache for arbitrary commands. It runs a command under a system
call tracer and records what the command looked at: the files it read, the
paths it checked, the directories it listed. The next time the same command
runs and none of that has changed, xcache restores the files the command wrote
and replays its output instead of running it.

Nothing needs to be configured. There are no cache keys to write and no list
of inputs to keep up to date.

xcache is early. It runs on Linux (x86_64 and aarch64), and the cache format
and command line will change.

## Installation

There are no binaries yet. Build from source with Rust 1.88 or newer:

```sh
cargo install --path .
```

xcache needs Linux 5.3 or newer, and traces fastest on 6.6 or newer. It has
been tested on 6.8.

## Usage

### Running a command

Prefix a command with `xcache run --`:

```sh
xcache run -- make -j8
xcache run -- cargo test
xcache run -- npm run build
```

If the command has run before with the same arguments, working directory and
environment, and every file it depended on is unchanged, xcache restores its
result and prints something like
`xcache: hit, restored 44 outputs (the original run took 1.6s)`. Otherwise it
runs the command and records it. Either way the exit status is the command's.

### Finding out why a command missed

`xcache explain -- <command>` shows, for each cached result, the first input
that no longer matches.

`xcache run --report <file>` writes a JSON summary of the run: whether it hit,
why it was not cached, how many inputs and outputs it had, and where the time
went.

### Checking the cache with shadow mode

`xcache run --shadow -- <command>` runs the command even when it could be
restored, and compares the two results. Use it for a while before trusting
the cache with a new project. It reports one of:

- `correct`: same files, same output, same exit status.
- `nondeterministic`: the fresh run read exactly the same inputs but produced
  different output, or failed. A date written to a log file, the output of a
  parallel `make` interleaving differently, or a flaky test looks like this.
- `false_hit`: the fresh run depended on something the cached run didn't
  record. That is a bug in xcache. Please open an issue with the `--report`
  output.

Unless it finds a false hit, shadow mode then leaves the cached result in
place, as a hit would, so later commands see the same files with and without
`--shadow`. After a false hit it keeps the fresh result and removes the wrong
entry.

### Environment variables

Variables that change on every CI run, such as `GITHUB_SHA`, `GITHUB_RUN_ID`,
`PWD` and access tokens, are removed from the command's environment, so they
can't cause a miss and the command can't depend on them. If a command needs
one, pass it with `--pass-env GITHUB_SHA`; it then becomes part of the cache
key.

### GitHub Actions

Until there is a remote cache, keep the cache directory between runs with
`actions/cache`:

```yaml
- uses: actions/cache@v6
  with:
    path: ~/.cache/xcache
    key: xcache-${{ runner.os }}-${{ runner.arch }}-${{ github.sha }}
    restore-keys: xcache-${{ runner.os }}-${{ runner.arch }}-

- run: npm ci
- run: xcache run -- npm run build
- run: xcache run -- npm test

- run: xcache gc --max-size 2G
  if: always()
```

`npm ci` is not wrapped because it downloads packages, and commands that use
the network are never cached.

Some tools keep caches of their own that change on every run, so a step that
reads them never hits. Turn them off in jobs that use xcache:

- Node's module compile cache, which npm enables:
  `NODE_DISABLE_COMPILE_CACHE=1`.
- npm's debug logs, which npm rotates by listing their directory:
  `npm_config_logs_max=0`.
- Go's usage counters, which the go command updates on every run, where the
  home directory persists between runs: `go telemetry off`.

### Cache location and size

The cache is stored in `$XCACHE_DIR`, or `$XDG_CACHE_HOME/xcache`, or
`~/.cache/xcache`. `xcache gc --max-size 2G` drops the least recently used
results until the cache fits.

## What is not cached

A command still runs normally, but its result is not stored, when it:

- exits with a non-zero status;
- connects to the network, or to a local service it didn't start itself
  (Docker, a database, a DNS resolver), or accepts a connection from one;
- leaves processes running after it exits (xcache kills them);
- creates namespaces, mounts filesystems, or calls `chroot`;
- renames a directory it didn't create;
- has one of its input files changed by another process while it runs.

xcache prints the reason when this happens.

A connection that finds nothing, such as glibc checking for `nscd`'s socket or
probing `localhost` to sort the addresses it resolved, only shows that nothing
is there. That is recorded as an input, so the command misses if a service
appears there later.

## Known caveats

- The clock and random numbers can't be traced. If a command writes a
  timestamp into a file, a cache hit restores the old timestamp.
- Reads under `/proc`, `/sys` and `/dev` (except `/dev/shm`) are not tracked.
  CPU counts and cgroup limits count as properties of the machine.
- Files are compared by content, never by modification time, so touching a
  file without changing it doesn't cause a miss. Restored files are dated in
  the order the original run left them, ending at the time of the restore, and
  are owned by the current user.
- Git's index and reflogs are compared without the times and identities they
  keep about the checkout, so a command that prints reflog dates or names gets
  the cached ones on a hit.
- A miss is slower than running the command directly, because every system
  call that looks at or changes the filesystem passes through xcache. See
  [Performance](#performance).
- Many tools check whether their outputs exist, so in a working tree that
  already has build output the first run misses once.
- For a build script without `rerun-if-changed`, cargo stores the newest
  modification time of the package's files. After a hit in a fresh checkout,
  a cargo command that misses reruns that package's build script once.
- Build daemons (Gradle, Bazel, sccache) outlive the command that starts them,
  so those runs are not cached. Run Gradle without them:
  `./gradlew --no-daemon -Pkotlin.compiler.execution.strategy=in-process build`.
- If ptrace or seccomp filters are not allowed, as in some sandboxes, xcache
  says so and runs the command without caching.

## Performance

The [shadow corpus](docs/corpus.md) runs the build and test steps of 29 open
source projects (Go, Rust, Node, Python, Gradle and CMake) from fresh checkouts
on GitHub's x86_64 and aarch64 runners. In the [latest
results](docs/corpus-results.md):

- 93% of steps are cacheable, and all of those hit from a fresh checkout of the
  same commit.
- A miss takes 21% longer than running the command directly (median), from +8%
  for CMake to +29% for Gradle.
- A hit is 15x to 48x faster than running the step (median per ecosystem).
- Shadow mode found no wrong result.

Those results are from before reads were recorded through a seccomp listener,
which makes a miss cheaper. [docs/design.md](docs/design.md#open-problems) has
what was measured since, and what remains slow.

## How it works

Every way a process can learn about the filesystem goes through a system call.
xcache starts the command under ptrace with a seccomp filter. The filter shows
the calls that only look at the filesystem to a thread of xcache while the
caller waits, stops the calls that change it in ptrace, and lets everything
else run. `--tracer ptrace` stops both kinds in ptrace, which is also what
happens on kernels before 5.6 and in containers that refuse `pidfd_getfd`, as
Docker's default seccomp profile does. For each call xcache records an input
(file content, whether a path exists, the names in a directory) or an output.
Before a write reaches the kernel, it captures the state the command depended
on, so a file that is read and then rewritten is recorded with its original
content.

Each stored result lists its inputs with the state they had. A lookup checks
those states against the filesystem and restores the first result that
matches. [docs/design.md](docs/design.md) has the details and a map of the
code.

## Roadmap

The long-term goal is for every build and test step, in CI and on developer
machines, to be cached this way and shared between machines, without anyone
writing a cache key. Roughly in order:

- A remote cache using the
  [Bazel Remote Execution API](https://github.com/bazelbuild/remote-apis), and
  a GitHub Action.
- Dropping repeated path lookups before they reach xcache, for example with
  eBPF, so a miss costs less than 10% over an uncached run on every step.
- Signed cache entries, and read-only access for untrusted pull requests.
- [SLSA](https://slsa.dev/) provenance built from the recorded inputs.

## Related work

- [BuildXL](https://github.com/microsoft/BuildXL) uses observed file accesses
  as cache keys. xcache applies the same idea to single commands.
- [Rattle](https://github.com/ndmitchell/rattle) is a build system that learns
  dependencies by tracing commands.
- [ccache](https://ccache.dev/) and [sccache](https://github.com/mozilla/sccache)
  cache compiler invocations.
- Earthly's [ucacher](https://earthly.dev/blog/ucacher/) traced GitHub Actions
  steps to skip them.

## Development

The tests need Linux with `sh`, `gcc`, `go`, `python3` and `git`.
[dev/lima.yaml](dev/lima.yaml) describes a VM that has them.

```sh
cargo test
```

Most of the tests in [tests/traps/](tests/traps) try to make xcache return a
wrong result, for example with a header that shadows another on the include
path or a file rewritten in place. A fix for a false hit should start with a
new test there. CI runs them on x86_64 and aarch64, since x86_64 also has the
older system calls and the 32-bit ABI.

## License

Apache-2.0
