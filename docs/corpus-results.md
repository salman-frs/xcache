# Shadow corpus results

Measured on 2026-11-10 with xcache at `a007bb8`, on GitHub's `ubuntu-24.04`
(x86_64) and `ubuntu-24.04-arm` (aarch64) runners:
[workflow run](https://github.com/salman-frs/xcache/actions/runs/42901211496).
[corpus.md](corpus.md) describes what each number means.

| | |
|---|---|
| Projects | 29, on both architectures |
| Cacheable steps | **93%** (132 of 142) |
| Hits from a fresh checkout of the same commit | **100%** of cacheable steps (132 of 132) |
| Median overhead on a miss | **+21%** |
| Hit rate across 6 consecutive commits | **18%** (156 of 852 step runs) |
| False hits | **0** wrong results; 4 shadow reports, explained below |
| Exit status changed by xcache | 0 |

| Ecosystem | Cacheable | Median miss overhead | Median hit speedup | Commit hits |
|---|---|---|---|---|
| C/CMake | 28/30 | +8% | 48x | 50/180 |
| Node | 30/30 | +17% | 27x | 30/180 |
| Rust | 20/20 | +17% | 21x | 10/120 |
| Go | 28/30 | +24% | 15x | 40/180 |
| Python | 20/20 | +24% | 18x | 14/120 |
| Java/Gradle | 6/12 | +29% | 38x | 12/72 |

## Decision

Over 60% of steps are cacheable and no false hit produced a wrong result, so
the next work is the faster tracer and the remote cache.

## False hits

Shadow mode reports 4, all in `cargo test` of ripgrep and just, at the first
commit. For a build script that declares no `rerun-if-changed`, cargo writes the
newest modification time of the package's files into its fingerprint. A fresh
checkout has new times, so after `cargo build` is restored, `cargo test` reruns
the build script (which runs `git`) and relinks the binary. The cached result
is the one a fresh run produces; only cargo's fingerprint files differ. The
cost is that a cargo command that misses after a hit redoes that package once.

Every false hit the corpus found along the way was either an xcache bug, now
fixed with a test in [tests/traps/](../tests/traps), or a gap in how shadow
mode compared runs:

| Found in | Cause | Test |
|---|---|---|
| make-style builds (analysis of `.git/index` misses) | a `stat` recorded size and mode, not what the modification time stands for, so a same-size edit behind an mtime check hit | `a_same_size_edit_behind_a_modification_time_check_misses` |
| spring-petclinic `gradle check` | real-time signals made the tracer exit with status 125 and kill the build | `real_time_signals_reach_the_command` |
| libuv `ctest` | checking each datagram's receiver was quadratic, so a test timed out only under xcache | `many_datagrams_to_its_own_sockets_stay_fast` |
| cargo and cmake in shadow mode | restored outputs were older than a fresh checkout's sources | `restored_outputs_are_newer_than_the_checkout_they_are_restored_into` |
| go test, cargo test in shadow mode | shadow mode left fresh-only files, lost hard links and kept the fresh result | `shadow_mode_leaves_what_a_hit_would_so_later_commands_see_the_same_files`, `shadow_mode_removes_files_only_the_fresh_run_created` |
| cargo's jobserver, which opens `/dev/fd/N` (corpus run of 2026-11-13) | xcache followed `/dev/fd` into its own descriptors and stored the files it had open as outputs, so restoring failed or would have overwritten them | `a_file_written_through_dev_fd_is_restored`, `a_file_read_through_dev_fd_is_an_input`, `a_file_reached_through_a_link_to_proc_self_is_not_cached` |
| Gradle, cargo, kotlinpoet in shadow mode | reads the cached run did as checks, or of files it had overwritten, counted as unrecorded | `reading_what_the_cached_run_only_checked_is_not_a_false_hit`, `reading_a_file_the_cached_run_overwrote_unseen_is_not_a_false_hit` |

## What is not cacheable

| Reason | Steps | Where |
|---|---|---|
| a local service it did not start | 10 | DNS resolver (chi, mockito), Docker for Testcontainers (spring-petclinic), libuv's tests |
| network access | 6 | Gradle plugins resolving hosts (mockito), libuv's tests |
| processes left running | 4 | mockito's Gradle build |
| renames a directory it did not create | 2 | libuv's tests |

These are what the commands do, not gaps in tracing.

## What changed to get here

The first run, before any fix, had 82% of steps cacheable and no Node step hit
from a fresh checkout. Each item below raised one of those numbers:

- `.git/index` and the reflogs are compared without their per-checkout stat
  data, times and identities: cargo and `go build` read them on every build.
- glibc checking for nscd, and probing addresses it resolved, are inputs rather
  than service connections.
- The tracer recognizes the command's own connections, sockets and timestamp
  changes, and files with names that are not UTF-8.
- Gradle runs without daemons, and Node without its compile cache and npm logs;
  the README recommends the same.
- Inputs are hashed in parallel, which cuts hashing on a miss by about a third.

## Per project

| Project | Arch | False hits | Cacheable | Miss overhead | Hit speedup | Warm hits | Commit hits |
|---|---|---|---|---|---|---|---|
| fmt (cmake) | aarch64 | 0 | 3/3 | +9% | 189x | 3/3 | 2/18 |
| fmt (cmake) | x86_64 | 0 | 3/3 | -0% | 297x | 3/3 | 2/18 |
| googletest (cmake) | aarch64 | 0 | 3/3 | +20% | 68x | 3/3 | 5/18 |
| googletest (cmake) | x86_64 | 0 | 3/3 | -6% | 140x | 3/3 | 5/18 |
| json-c (cmake) | aarch64 | 0 | 3/3 | +11% | 33x | 3/3 | 0/18 |
| json-c (cmake) | x86_64 | 0 | 3/3 | +127% | 16x | 3/3 | 0/18 |
| libuv (cmake) | aarch64 | 0 | 2/3 | +23% | 24x | 2/2 | 6/18 |
| libuv (cmake) | x86_64 | 0 | 2/3 | +7% | 63x | 2/2 | 6/18 |
| zlib (cmake) | aarch64 | 0 | 3/3 | -18% | 32x | 3/3 | 12/18 |
| zlib (cmake) | x86_64 | 0 | 3/3 | -23% | 34x | 3/3 | 12/18 |
| chi (go) | aarch64 | 0 | 2/3 | +12% | 14x | 2/2 | 2/18 |
| chi (go) | x86_64 | 0 | 2/3 | +11% | 17x | 2/2 | 2/18 |
| cobra (go) | aarch64 | 0 | 3/3 | +27% | 13x | 3/3 | 4/18 |
| cobra (go) | x86_64 | 0 | 3/3 | +22% | 18x | 3/3 | 4/18 |
| testify (go) | aarch64 | 0 | 3/3 | +18% | 25x | 3/3 | 13/18 |
| testify (go) | x86_64 | 0 | 3/3 | +12% | 38x | 3/3 | 13/18 |
| toml (go) | aarch64 | 0 | 3/3 | +48% | 9x | 3/3 | 1/18 |
| toml (go) | x86_64 | 0 | 3/3 | +26% | 16x | 3/3 | 1/18 |
| uuid (go) | aarch64 | 0 | 3/3 | +44% | 10x | 3/3 | 0/18 |
| uuid (go) | x86_64 | 0 | 3/3 | +31% | 14x | 3/3 | 0/18 |
| kotlinpoet (gradle) | aarch64 | 0 | 2/2 | +25% | 52x | 2/2 | 6/12 |
| kotlinpoet (gradle) | x86_64 | 0 | 2/2 | +32% | 59x | 2/2 | 6/12 |
| mockito (gradle) | aarch64 | 0 | 0/2 | +14% | n/a | 0/0 | 0/12 |
| mockito (gradle) | x86_64 | 0 | 0/2 | +21% | n/a | 0/0 | 0/12 |
| spring-petclinic (gradle) | aarch64 | 0 | 1/2 | +46% | 21x | 1/1 | 0/12 |
| spring-petclinic (gradle) | x86_64 | 0 | 1/2 | +58% | 23x | 1/1 | 0/12 |
| chalk (node) | aarch64 | 0 | 1/1 | +26% | 16x | 1/1 | 0/6 |
| chalk (node) | x86_64 | 0 | 1/1 | +20% | 16x | 1/1 | 0/6 |
| commander (node) | aarch64 | 0 | 3/3 | +11% | 44x | 3/3 | 12/18 |
| commander (node) | x86_64 | 0 | 3/3 | +9% | 46x | 3/3 | 12/18 |
| koa (node) | aarch64 | 0 | 2/2 | +60% | 20x | 2/2 | 0/12 |
| koa (node) | x86_64 | 0 | 2/2 | +42% | 21x | 2/2 | 0/12 |
| luxon (node) | aarch64 | 0 | 2/2 | +14% | 35x | 2/2 | 0/12 |
| luxon (node) | x86_64 | 0 | 2/2 | +12% | 33x | 2/2 | 0/12 |
| marked (node) | aarch64 | 0 | 4/4 | +7% | 38x | 4/4 | 3/24 |
| marked (node) | x86_64 | 0 | 4/4 | +6% | 39x | 4/4 | 3/24 |
| uuidjs (node) | aarch64 | 0 | 3/3 | +28% | 19x | 3/3 | 0/18 |
| uuidjs (node) | x86_64 | 0 | 3/3 | +30% | 12x | 3/3 | 0/18 |
| click (python) | aarch64 | 0 | 3/3 | +21% | 27x | 3/3 | 0/18 |
| click (python) | x86_64 | 0 | 3/3 | +16% | 42x | 3/3 | 0/18 |
| flask (python) | aarch64 | 0 | 2/2 | +32% | 14x | 2/2 | 3/12 |
| flask (python) | x86_64 | 0 | 2/2 | +27% | 13x | 2/2 | 3/12 |
| jinja (python) | aarch64 | 0 | 2/2 | +16% | 22x | 2/2 | 2/12 |
| jinja (python) | x86_64 | 0 | 2/2 | +28% | 8x | 2/2 | 2/12 |
| markupsafe (python) | aarch64 | 0 | 2/2 | +83% | 7x | 2/2 | 2/12 |
| markupsafe (python) | x86_64 | 0 | 2/2 | +57% | 10x | 2/2 | 2/12 |
| more-itertools (python) | aarch64 | 0 | 1/1 | +2% | 714x | 1/1 | 0/6 |
| more-itertools (python) | x86_64 | 0 | 1/1 | +2% | 802x | 1/1 | 0/6 |
| anyhow (rust) | aarch64 | 0 | 2/2 | -5% | 19x | 2/2 | 5/12 |
| anyhow (rust) | x86_64 | 0 | 2/2 | -1% | 21x | 2/2 | 5/12 |
| fd (rust) | aarch64 | 0 | 2/2 | +37% | 36x | 2/2 | 0/12 |
| fd (rust) | x86_64 | 0 | 2/2 | +30% | 62x | 2/2 | 0/12 |
| just (rust) | aarch64 | 1 | 2/2 | +25% | 19x | 2/2 | 0/12 |
| just (rust) | x86_64 | 1 | 2/2 | +76% | 21x | 2/2 | 0/12 |
| ripgrep (rust) | aarch64 | 1 | 2/2 | +9% | 19x | 2/2 | 0/12 |
| ripgrep (rust) | x86_64 | 1 | 2/2 | +54% | 19x | 2/2 | 0/12 |
| serde_json (rust) | aarch64 | 0 | 2/2 | +9% | 22x | 2/2 | 0/12 |
| serde_json (rust) | x86_64 | 0 | 2/2 | +4% | 31x | 2/2 | 0/12 |

Steps with nondeterministic output, such as test reports with timings, are
listed in the workflow's summary.
