# Shadow corpus

The corpus measures xcache on the build and test steps of popular open source
projects, so we know whether it is correct and worth using on real builds. The
projects are listed in [corpus/projects.toml](../corpus/projects.toml), pinned
to a commit, and the [Corpus workflow](../.github/workflows/corpus.yml) runs
each of them on x86_64 and aarch64 every week and whenever the corpus changes.

## What a run does

Each project is measured in phases. Every phase starts from a fresh shallow
checkout at the same path, made the way `actions/checkout` makes one, and from
the same home directory, which holds the dependencies that `setup` and `prime`
downloaded once. `setup` (for example `npm ci`) runs without xcache before the
steps, as it would in CI. Build caches such as `GOCACHE` and `target/` start
empty.

| Phase | Commit | How the steps run |
|---|---|---|
| `baseline` | oldest | without xcache |
| `cold` | oldest | `xcache run`, with an empty cache |
| `warm` | oldest | `xcache run` |
| `shadow` | oldest | `xcache run --shadow` |
| `commit-1` … `commit-6` | each later commit in turn | `xcache run --shadow` |

The commits are the pinned commit and the first-parent commits before it.

## What the summary reports

- **False hits**: shadow runs whose verdict was `false_hit`, with the inputs
  the cached run missed. Each one is a bug, and gets a test in
  [tests/traps.rs](../tests/traps.rs).
- **Cacheable**: steps whose cold run was stored, out of all steps. The
  summary groups the reasons the others were not stored.
- **Miss overhead**: wall time of the cold phase over the baseline, both
  measured from the outside, so it includes hashing and storing the outputs.
- **Hit speedup**: baseline time over warm time for the steps that hit.
- **Warm hits**: cacheable steps that hit from a fresh checkout of the same
  commit. Anything short of all of them means some input differs between
  checkouts.
- **Commit hits**: step runs that hit across the consecutive commits. A step
  that reads every source file misses whenever any of them changes, so this
  depends on the project's history as much as on xcache.
- **Nondeterministic** steps and steps whose **exit status changed** under
  xcache are listed per project.

Shadow mode leaves the cached result in place when it confirms a hit, so the
steps after it see what they would see without `--shadow`, and the hit rates
are the same as in normal use.

## Running it locally

The harness needs Python 3.11, git, and the toolchains of the projects you
pick. On Linux:

```sh
cargo build --release
python3 corpus/corpus.py run --xcache target/release/xcache koa zlib
python3 corpus/corpus.py report results/*.json
```

`run` writes `results/<project>-<arch>.json`, plus the logs and xcache reports
of every step under `results/logs/`. It works in `/tmp/xcache-corpus` and
deletes each project's directory when the project is done, unless you pass
`--keep`.

To run the workflow on GitHub for some of the projects:

```sh
gh workflow run corpus.yml -f projects="koa zlib"
```

## Adding a project

Pick a project whose tests pass offline once its dependencies are installed,
pin `rev` to a commit on its default branch, and list the commands a CI job
would run as `steps`. Put dependency downloads in `setup` (every phase) or
`prime` (once). A project that fails without xcache measures nothing.
