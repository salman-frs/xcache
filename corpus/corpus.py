#!/usr/bin/env python3
"""Runs real projects' build and test steps under xcache and summarizes the results.

    corpus.py list [NAME...]                projects and their ecosystems, as JSON
    corpus.py run --xcache BIN NAME...      measure projects, writing results/NAME-ARCH.json
    corpus.py report results/*.json         write the summary as Markdown and JSON

See docs/corpus.md for what each phase measures.
"""

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

CORPUS = Path(__file__).with_name("projects.toml")
STEP_TIMEOUT_SECONDS = 45 * 60
DIFFERENCES_KEPT = 20


@dataclass
class Project:
    name: str
    repo: str
    rev: str
    ecosystem: str
    setup: list[str]
    prime: list[str]
    steps: list[str]
    env: dict[str, str]
    commits: int


@dataclass
class Phase:
    name: str
    commit: str
    xcache_args: list[str] | None


def load_corpus(path: Path = CORPUS) -> list[Project]:
    corpus = tomllib.loads(path.read_text())
    ecosystems = corpus["ecosystem"]
    projects = []
    for entry in corpus["project"]:
        ecosystem = ecosystems[entry["ecosystem"]]
        projects.append(
            Project(
                name=entry["name"],
                repo=entry["repo"],
                rev=entry["rev"],
                ecosystem=entry["ecosystem"],
                setup=entry.get("setup", ecosystem.get("setup", [])),
                prime=entry.get("prime", []),
                steps=entry["steps"],
                env={**ecosystem.get("env", {}), **entry.get("env", {})},
                commits=entry.get("commits", corpus["commits"]),
            )
        )
    return projects


def measurement_plan(commits: list[str]) -> list[Phase]:
    first, *later = commits
    plan = [
        Phase("baseline", first, None),
        Phase("cold", first, []),
        Phase("warm", first, []),
        Phase("shadow", first, ["--shadow"]),
    ]
    plan += [Phase(f"commit-{index}", commit, ["--shadow"]) for index, commit in enumerate(later, start=1)]
    return plan


class Workspace:
    """Everything one project touches, at fixed paths so every phase sees the same invocation."""

    def __init__(self, root: Path, project: Project, xcache: Path):
        self.project = project
        self.xcache = xcache
        self.root = root / project.name
        self.mirror = self.root / "mirror.git"
        self.src = self.root / "src"
        self.home = self.root / "home"
        self.home_snapshot = self.root / "home.snapshot"
        self.tmp = self.root / "tmp"
        self.store = self.root / "store"
        self.logs = self.root / "logs"
        self.reports = self.root / "reports"

    def create(self) -> None:
        remove_tree(self.root)
        for directory in (self.home, self.tmp, self.store, self.logs, self.reports):
            directory.mkdir(parents=True)

    def fetch_commits(self) -> list[str]:
        """The pinned revision and the first-parent commits before it, oldest first."""
        depth = str(self.project.commits + 1)
        git("init", "--quiet", "--bare", str(self.mirror))
        git("-C", str(self.mirror), "config", "uploadpack.allowAnySHA1InWant", "true")
        git("-C", str(self.mirror), "fetch", "--quiet", "--no-tags", "--depth", depth, self.repo_url, self.project.rev)
        listed = git("-C", str(self.mirror), "rev-list", "--first-parent", "-n", depth, self.project.rev)
        return list(reversed(listed.split()))

    @property
    def repo_url(self) -> str:
        return f"https://github.com/{self.project.repo}.git"

    def check_out(self, commit: str) -> None:
        """A fresh shallow checkout, the way actions/checkout makes one."""
        remove_tree(self.src)
        git("init", "--quiet", str(self.src))
        git("-C", str(self.src), "remote", "add", "origin", self.repo_url)
        git("-C", str(self.src), "fetch", "--quiet", "--no-tags", "--depth", "1", f"file://{self.mirror}", commit)
        git("-C", str(self.src), "checkout", "--quiet", "--detach", "FETCH_HEAD")

    def prime_home(self, commit: str) -> None:
        """Download dependencies once and keep the resulting home directory, like a restored CI cache."""
        self.check_out(commit)
        for command in self.project.setup + self.project.prime:
            self.shell(command, self.logs / "prime.log")
        self.stop_leftover_processes()
        remove_tree(self.home_snapshot)
        subprocess.run(["cp", "-a", str(self.home), str(self.home_snapshot)], check=True)

    def start_phase(self, phase: Phase) -> None:
        """Each phase stands for a CI run on a new machine, where xcache's per-boot stat cache is empty."""
        remove_tree(self.home)
        subprocess.run(["cp", "-a", str(self.home_snapshot), str(self.home)], check=True)
        remove_tree(self.tmp)
        self.tmp.mkdir()
        remove_tree(self.store / "stat-cache")
        self.check_out(phase.commit)
        for command in self.project.setup:
            self.shell(command, self.logs / f"{phase.name}.setup.log")

    def stop_leftover_processes(self) -> None:
        """Build daemons started without xcache outlive their phase; nothing else runs from this workspace."""
        subprocess.run(["pkill", "-KILL", "-f", "--", f"{self.root}/"], check=False)

    def save_logs(self, destination: Path) -> None:
        remove_tree(destination)
        shutil.copytree(self.logs, destination / "logs")
        shutil.copytree(self.reports, destination / "reports")

    def run_step(self, phase: Phase, index: int, step: str) -> dict:
        argv = shlex.split(step)
        report = self.reports / f"{phase.name}.{index}.json"
        if phase.xcache_args is not None:
            argv = [str(self.xcache), "run", "--report", str(report), *phase.xcache_args, "--", *argv]
        log = self.logs / f"{phase.name}.{index}.log"
        started = time.monotonic()
        exit_code = run_logged(argv, self.src, self.environment(), log)
        run = {
            "phase": phase.name,
            "commit": phase.commit,
            "step": step,
            "exit_code": exit_code,
            "wall_ms": round((time.monotonic() - started) * 1000),
        }
        if phase.xcache_args is not None:
            run["xcache"] = read_report(report)
        return run

    def shell(self, command: str, log: Path) -> None:
        exit_code = run_logged(["bash", "-euo", "pipefail", "-c", command], self.src, self.environment(), log)
        if exit_code != 0:
            raise SetupFailed(f"`{command}` exited with status {exit_code}; see {log}")

    def environment(self) -> dict[str, str]:
        real_home = Path.home()
        env = dict(os.environ)
        env.setdefault("RUSTUP_HOME", str(real_home / ".rustup"))
        home = str(self.home)
        env.update(
            HOME=home,
            TMPDIR=str(self.tmp),
            XCACHE_DIR=str(self.store),
            XDG_CACHE_HOME=f"{home}/.cache",
            XDG_CONFIG_HOME=f"{home}/.config",
            XDG_DATA_HOME=f"{home}/.local/share",
            CARGO_HOME=f"{home}/.cargo",
            GOPATH=f"{home}/go",
            GRADLE_USER_HOME=f"{home}/.gradle",
            npm_config_cache=f"{home}/.npm",
        )
        for name in ("GOCACHE", "GOMODCACHE", "UV_CACHE_DIR", "PIP_CACHE_DIR", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR"):
            env.pop(name, None)
        env.update(self.project.env)
        return env


class SetupFailed(Exception):
    pass


def run_project(project: Project, xcache: Path, work: Path, results: Path) -> dict:
    workspace = Workspace(work, project, xcache)
    workspace.create()
    result = {
        "project": project.name,
        "repo": project.repo,
        "ecosystem": project.ecosystem,
        "arch": platform.machine(),
        "xcache": subprocess.run([str(xcache), "--version"], capture_output=True, text=True).stdout.strip(),
        "steps": project.steps,
        "commits": [],
        "runs": [],
        "errors": [],
    }
    output = results / f"{project.name}-{result['arch']}.json"
    try:
        result["commits"] = workspace.fetch_commits()
        workspace.prime_home(result["commits"][0])
    except (SetupFailed, subprocess.CalledProcessError) as error:
        result["errors"].append(f"preparing: {error}")
        write_json(output, result)
        workspace.save_logs(results / "logs" / output.stem)
        return result

    for phase in measurement_plan(result["commits"]):
        log(f"{project.name}: {phase.name} at {phase.commit[:12]}")
        try:
            workspace.start_phase(phase)
        except (SetupFailed, subprocess.CalledProcessError) as error:
            result["errors"].append(f"{phase.name}: {error}")
            continue
        for index, step in enumerate(project.steps):
            run = workspace.run_step(phase, index, step)
            result["runs"].append(run)
            log(f"  {step}: {describe_run(run)}")
        workspace.stop_leftover_processes()
        write_json(output, result)
    workspace.save_logs(results / "logs" / output.stem)
    return result


def describe_run(run: dict) -> str:
    seconds = f"{run['wall_ms'] / 1000:.1f}s"
    report = run.get("xcache")
    if report is None:
        return f"exit {run['exit_code']} in {seconds}"
    verdict = f", shadow {report['shadow']}" if "shadow" in report else ""
    reasons = f" ({'; '.join(report['reasons'])})" if report.get("reasons") else ""
    return f"{report['outcome']}{verdict}, exit {run['exit_code']} in {seconds}{reasons}"


def read_report(path: Path) -> dict:
    try:
        report = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"outcome": "no_report"}
    report["differences"] = report.get("differences", [])[:DIFFERENCES_KEPT]
    return report


def run_logged(argv: list[str], cwd: Path, env: dict[str, str], log: Path) -> int:
    with log.open("ab") as output:
        output.write(f"$ {shlex.join(argv)}\n".encode())
        output.flush()
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=STEP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, 9)
            process.wait()
            output.write(b"\ncorpus: timed out\n")
            return 124


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def remove_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    try:
        shutil.rmtree(path)
    except PermissionError:
        subprocess.run(["chmod", "-R", "u+w", str(path)], check=True)
        shutil.rmtree(path)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


# Summary


@dataclass
class ProjectSummary:
    name: str
    arch: str
    ecosystem: str
    steps: int
    cacheable: int
    not_cacheable_reasons: list[str]
    miss_overhead: float | None
    hit_speedup: float | None
    warm_hits: int
    warm_cacheable: int
    commit_runs: int
    commit_hits: int
    false_hits: list[dict]
    nondeterministic: list[dict]
    changed_exit_status: list[dict]
    errors: list[str]


def summarize_project(result: dict) -> ProjectSummary:
    runs = result["runs"]
    by_phase = {}
    for run in runs:
        by_phase.setdefault(run["phase"], {})[run["step"]] = run
    baseline, cold, warm = (by_phase.get(name, {}) for name in ("baseline", "cold", "warm"))
    commit_runs = [run for run in runs if run["phase"].startswith("commit-")]

    cacheable_steps = {step for step, run in cold.items() if run["xcache"]["outcome"] == "miss"}
    reasons = [
        f"`{step}`: {'; '.join(run['xcache'].get('reasons', [])) or run['xcache']['outcome']}"
        for step, run in cold.items()
        if step not in cacheable_steps
    ]
    both = [step for step in cold if step in baseline]
    miss_overhead = ratio(sum(cold[s]["wall_ms"] for s in both), sum(baseline[s]["wall_ms"] for s in both))
    warm_hit_steps = [step for step, run in warm.items() if run["xcache"]["outcome"] == "hit"]
    hit_speedup = ratio(sum(baseline[s]["wall_ms"] for s in warm_hit_steps if s in baseline),
                        sum(warm[s]["wall_ms"] for s in warm_hit_steps))

    def finding(run: dict) -> dict:
        return {"phase": run["phase"], "commit": run["commit"], "step": run["step"],
                "differences": run["xcache"].get("differences", [])}

    shadowed = [run for run in runs if run.get("xcache", {}).get("shadow")]
    changed_exit = [
        {"phase": run["phase"], "step": run["step"], "baseline": baseline[run["step"]]["exit_code"],
         "xcache": run["exit_code"]}
        for phase in (cold, warm)
        for run in phase.values()
        if run["step"] in baseline and run["exit_code"] != baseline[run["step"]]["exit_code"]
    ]
    return ProjectSummary(
        name=result["project"],
        arch=result["arch"],
        ecosystem=result["ecosystem"],
        steps=len(cold),
        cacheable=len(cacheable_steps),
        not_cacheable_reasons=reasons,
        miss_overhead=None if miss_overhead is None else miss_overhead - 1,
        hit_speedup=hit_speedup,
        warm_hits=len(warm_hit_steps),
        warm_cacheable=len(cacheable_steps),
        commit_runs=len(commit_runs),
        commit_hits=sum(run["xcache"]["outcome"] == "hit" for run in commit_runs),
        false_hits=[finding(run) for run in shadowed if run["xcache"]["shadow"] == "false_hit"],
        nondeterministic=[finding(run) for run in shadowed if run["xcache"]["shadow"] == "nondeterministic"],
        changed_exit_status=changed_exit,
        errors=result["errors"],
    )


def ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def reason_category(reason: str) -> str:
    """Groups reasons that differ only in a path, port or address."""
    reason = re.sub(r"exited with status \d+", "exited with a non-zero status", reason)
    return re.split(r" to |: | \(", reason, maxsplit=1)[0]


def decision(false_hits: int, cacheable_share: float) -> str:
    if false_hits:
        return "Fix the false hits before anything else."
    if cacheable_share < 0.4:
        return "Raise the share of cacheable steps first (network allowlists, daemon support)."
    if cacheable_share > 0.6:
        return "Move on to the faster tracer and the remote cache."
    return "Between the thresholds: look at the top reasons before choosing."


def render_report(summaries: list[ProjectSummary]) -> str:
    steps = sum(s.steps for s in summaries)
    cacheable = sum(s.cacheable for s in summaries)
    false_hits = sum(len(s.false_hits) for s in summaries)
    commit_runs = sum(s.commit_runs for s in summaries)
    commit_hits = sum(s.commit_hits for s in summaries)
    overheads = sorted(s.miss_overhead for s in summaries if s.miss_overhead is not None)
    share = cacheable / steps if steps else 0.0

    lines = [
        "# xcache shadow corpus",
        "",
        f"- Projects: {len({s.name for s in summaries})} ({len(summaries)} runs across "
        f"{', '.join(sorted({s.arch for s in summaries}))})",
        f"- False hits: **{false_hits}**",
        f"- Cacheable steps: **{percent(share)}** ({cacheable} of {steps})",
        f"- Median overhead on a miss: **{percent(median(overheads))}**",
        f"- Hit rate across consecutive commits: **{percent(ratio(commit_hits, commit_runs))}** "
        f"({commit_hits} of {commit_runs} step runs)",
        "",
        f"Decision: {decision(false_hits, share)}",
        "",
        "| Project | Arch | False hits | Cacheable | Miss overhead | Hit speedup | Warm hits | Commit hits |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in sorted(summaries, key=lambda s: (s.ecosystem, s.name, s.arch)):
        lines.append(
            f"| {s.name} ({s.ecosystem}) | {s.arch} | {len(s.false_hits)} | {s.cacheable}/{s.steps} "
            f"| {signed_percent(s.miss_overhead)} | {times(s.hit_speedup)} | {s.warm_hits}/{s.warm_cacheable} "
            f"| {s.commit_hits}/{s.commit_runs} |"
        )

    reasons: dict[str, int] = {}
    for s in summaries:
        for reason in s.not_cacheable_reasons:
            for part in reason.split(": ", 1)[1].split("; "):
                category = reason_category(part)
                reasons[category] = reasons.get(category, 0) + 1
    if reasons:
        lines += ["", "## Why steps were not cacheable", "", "| Reason | Steps |", "|---|---|"]
        lines += [f"| {reason} | {count} |" for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1])]

    lines += ["", "## Details", ""]
    for s in sorted(summaries, key=lambda s: (s.ecosystem, s.name, s.arch)):
        notes = []
        notes += [f"- not cacheable: {reason}" for reason in s.not_cacheable_reasons]
        notes += [f"- **false hit** in {f['phase']} at {f['commit'][:12]}, `{f['step']}`: "
                  f"{'; '.join(f['differences'][:5])}" for f in s.false_hits]
        notes += [f"- nondeterministic in {f['phase']}, `{f['step']}`: {'; '.join(f['differences'][:3])}"
                  for f in s.nondeterministic]
        notes += [f"- **exit status changed** in {c['phase']}, `{c['step']}`: {c['baseline']} without xcache, "
                  f"{c['xcache']} with it" for c in s.changed_exit_status]
        notes += [f"- harness error: {error}" for error in s.errors]
        if notes:
            lines += [f"### {s.name} ({s.arch})", "", *notes, ""]
    return "\n".join(lines).rstrip() + "\n"


def median(values: list[float]) -> float | None:
    if not values:
        return None
    middle = len(values) // 2
    return values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2


def percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def signed_percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+.0%}"


def times(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f}x"


# Command line


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="print projects and their ecosystems as JSON")
    listing.add_argument("names", nargs="*", metavar="NAME", help="only these projects")
    run = commands.add_parser("run", help="measure projects")
    run.add_argument("--xcache", type=Path, required=True, help="the xcache binary to measure")
    run.add_argument("--work", type=Path, default=Path("/tmp/xcache-corpus"), help="scratch directory")
    run.add_argument("--results", type=Path, default=Path("results"), help="where to write NAME.json")
    run.add_argument("--keep", action="store_true", help="keep each project's scratch directory")
    run.add_argument("names", nargs="+", metavar="NAME")
    report = commands.add_parser("report", help="summarize results")
    report.add_argument("results", nargs="+", type=Path)
    report.add_argument("--json", type=Path, help="also write the summary as JSON")
    args = parser.parse_args()

    projects = {project.name: project for project in load_corpus()}
    if args.command in ("list", "run"):
        unknown = [name for name in args.names if name not in projects]
        if unknown:
            parser.error(f"unknown projects: {', '.join(unknown)}")
    if args.command == "list":
        chosen = args.names or list(projects)
        print(json.dumps([{"name": name, "ecosystem": projects[name].ecosystem} for name in chosen]))
    elif args.command == "run":
        for name in args.names:
            run_project(projects[name], args.xcache.resolve(), args.work, args.results)
            if not args.keep:
                remove_tree(args.work / name)
    else:
        summaries = [summarize_project(json.loads(path.read_text())) for path in args.results]
        print(render_report(summaries), end="")
        if args.json:
            write_json(args.json, {"projects": [vars(s) for s in summaries]})
    return 0


if __name__ == "__main__":
    sys.exit(main())
