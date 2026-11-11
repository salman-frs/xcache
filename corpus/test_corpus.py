import re
import unittest

import corpus


def run(phase: str, step: str, wall_ms: int, outcome: str | None = None, **report) -> dict:
    result = {"phase": phase, "commit": "c0ffee", "step": step, "exit_code": 0, "wall_ms": wall_ms}
    if outcome is not None:
        result["xcache"] = {"outcome": outcome, **report}
    return result


class ProjectsTest(unittest.TestCase):
    def test_every_project_is_pinned_and_has_steps(self):
        projects = corpus.load_corpus()
        names = [project.name for project in projects]
        self.assertEqual(len(names), len(set(names)), "project names must be unique")
        for project in projects:
            with self.subTest(project.name):
                self.assertRegex(project.rev, re.compile(r"^[0-9a-f]{40}$"))
                self.assertTrue(project.steps)


class SummaryTest(unittest.TestCase):
    def test_phases_start_cold_then_follow_the_commits(self):
        plan = corpus.measurement_plan(["old", "mid", "new"])
        self.assertEqual(
            [(phase.name, phase.commit, phase.xcache_args) for phase in plan],
            [
                ("baseline", "old", None),
                ("cold", "old", []),
                ("warm", "old", []),
                ("shadow", "old", ["--shadow"]),
                ("commit-1", "mid", ["--shadow"]),
                ("commit-2", "new", ["--shadow"]),
            ],
        )

    def test_summary_counts_cacheable_steps_hits_and_false_hits(self):
        result = {
            "project": "demo",
            "arch": "x86_64",
            "ecosystem": "go",
            "errors": [],
            "runs": [
                run("baseline", "build", 1000),
                run("baseline", "test", 2000),
                run("cold", "build", 1200, "miss"),
                run("cold", "test", 2000, "not_cached", reasons=["network access to 1.1.1.1:443"]),
                run("warm", "build", 50, "hit"),
                run("warm", "test", 2000, "not_cached"),
                run("commit-1", "build", 60, "hit", shadow="false_hit", differences=["/out differs"]),
                run("commit-1", "test", 2000, "not_cached"),
            ],
        }
        summary = corpus.summarize_project(result)
        self.assertEqual((summary.steps, summary.cacheable, summary.warm_hits), (2, 1, 1))
        self.assertEqual(summary.not_cacheable, {"test": ["network access to 1.1.1.1:443"]})
        self.assertAlmostEqual(summary.miss_overhead, 0.2 / 3)
        self.assertAlmostEqual(summary.hit_speedup, 20)
        self.assertEqual((summary.commit_hits, summary.commit_runs), (1, 2))
        self.assertEqual([finding["differences"] for finding in summary.false_hits], [["/out differs"]])

    def test_reasons_that_differ_only_in_detail_share_a_category(self):
        reasons = [
            "connects to a local service it did not start (port 5432)",
            "connects to a local service it did not start (port 6379)",
            "network access to 1.1.1.1:443",
            "exited with status 2",
        ]
        self.assertEqual(
            corpus.distinct_reasons(reasons),
            [
                "connects to a local service it did not start (port 5432)",
                "network access to 1.1.1.1:443",
                "exited with status 2",
            ],
        )


if __name__ == "__main__":
    unittest.main()
