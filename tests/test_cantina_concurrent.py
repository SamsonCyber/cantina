"""Tests for concurrent recon isolation + score metrics (real shipped code)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from cantina import Scanner, run_tasks_isolated  # noqa: E402
from cantina_score import compare_scores, score_scan, score_tool_use  # noqa: E402
from cantina_bench import (  # noqa: E402
    run_benchmark,
    run_concurrent_recon_simulation,
    score_fixture,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "cantina_bench"


class TestRunTasksIsolated:
    def test_parallel_success(self):
        tasks = ["a", "b", "c"]
        seen = []

        def work(t):
            seen.append(t)
            time.sleep(0.02)
            return t.upper()

        results = run_tasks_isolated(tasks, work, max_workers=3)
        assert len(results) == 3
        assert all(r["ok"] for r in results)
        assert {r["result"] for r in results} == {"A", "B", "C"}
        assert set(seen) == set(tasks)

    def test_one_worker_failure_does_not_abort_siblings(self):
        def work(t):
            if t == "bad":
                raise ValueError("boom")
            time.sleep(0.01)
            return t

        results = run_tasks_isolated(["ok1", "bad", "ok2"], work, max_workers=3)
        assert len(results) == 3
        ok = [r for r in results if r["ok"]]
        bad = [r for r in results if not r["ok"]]
        assert len(ok) == 2
        assert len(bad) == 1
        assert "ValueError" in (bad[0]["error"] or "")
        assert {r["result"] for r in ok} == {"ok1", "ok2"}

    def test_never_raises_on_worker_error(self):
        def work(_t):
            raise RuntimeError("always")

        results = run_tasks_isolated([1, 2], work, max_workers=2)
        assert len(results) == 2
        assert all(not r["ok"] for r in results)


class TestScoreToolUseAndSpeed:
    def test_score_tool_use_counts(self):
        log = [
            {
                "ran": ["whatweb", "dirbust"],
                "skipped": ["nikto: skip"],
                "duration_ms": 10.0,
            },
            {"ran": ["smbclient_null"], "skipped": [], "duration_ms": 5.0},
        ]
        m = score_tool_use(log, worker_errors=1)
        assert m["tools_run"] == 3.0
        assert m["tools_skipped"] == 1.0
        assert m["services_recon"] == 2.0
        assert m["worker_errors"] == 1.0
        assert m["decision_duration_ms"] == 15.0
        assert 0 < m["tool_efficiency"] <= 100

    def test_score_scan_includes_speed_and_tools(self):
        ports = {
            22: {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH"},
            80: {"port": 80, "proto": "tcp", "service": "http", "version": "nginx"},
        }
        sc = score_scan(
            ports,
            [{"severity": "WARNING", "category": "Web", "message": "x"}],
            label="t",
            mode="test",
            duration_ms=42.5,
            decision_log=[{"ran": ["a"], "skipped": ["b: no"]}],
            worker_errors=0,
        )
        m = sc["metrics"]
        assert m["duration_ms"] == 42.5
        assert m["tools_run"] == 1.0
        assert m["tools_skipped"] == 1.0
        assert "composite" in m
        assert sc["duration_ms"] == 42.5

    def test_compare_duration_lower_is_better(self):
        a = score_scan({}, [], label="a", duration_ms=100.0)
        b = score_scan({}, [], label="b", duration_ms=50.0)
        d = compare_scores(a, b)
        assert d["metrics"]["duration_ms"]["verdict"] == "improve"


class TestBuildReconTasksAndConcurrent:
    def test_build_recon_tasks_multi_service(self, tmp_path):
        sc = Scanner("10.10.10.1", str(tmp_path))
        sc.tcp_ports = {
            22: {"port": 22, "proto": "tcp", "service": "ssh", "version": ""},
            80: {"port": 80, "proto": "tcp", "service": "http", "version": "nginx"},
            445: {"port": 445, "proto": "tcp", "service": "microsoft-ds", "version": ""},
            3306: {"port": 3306, "proto": "tcp", "service": "mysql", "version": ""},
        }
        tasks = sc.build_recon_tasks()
        kinds = {t[0] for t in tasks}
        assert "http" in kinds and "smb" in kinds and "ssh" in kinds and "mysql" in kinds
        assert len(tasks) >= 4

    def test_run_recon_concurrent_isolates_and_logs(self, tmp_path):
        sc = Scanner("10.10.10.1", str(tmp_path))
        sc.tcp_ports = {
            80: {"port": 80, "proto": "tcp", "service": "http", "version": "nginx"},
            445: {"port": 445, "proto": "tcp", "service": "microsoft-ds", "version": ""},
            22: {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH"},
        }
        tasks = sc.build_recon_tasks()
        assert len(tasks) >= 2

        def stub(svc, port, extra):
            if svc == "smb":
                raise RuntimeError("smb boom")
            sc._log_decision(
                svc, port,
                [{"tool": f"{svc}_ok", "run": True, "reason": "test", "weight": "light"}],
                duration_ms=1.0,
            )

        sc._recon_dispatch = stub  # type: ignore[method-assign]
        results = sc.run_recon_concurrent(tasks, max_workers=3)
        assert len(results) == len(tasks)
        ok = [r for r in results if r["ok"]]
        bad = [r for r in results if not r["ok"]]
        assert len(ok) >= 2
        assert len(bad) == 1
        assert len(sc.recon_errors) == 1
        # survivors still logged decisions
        svcs = {d["svc"] for d in sc.decision_log}
        assert "http" in svcs or "ssh" in svcs


class TestBenchLoop:
    def test_score_fixture_has_required_metrics(self):
        sc = score_fixture(FIXTURE, mode="optimized", label="t")
        m = sc["metrics"]
        for key in ("composite", "duration_ms", "tools_run", "tools_skipped", "completeness"):
            assert key in m, key
            assert isinstance(m[key], (int, float))

    def test_run_benchmark_twice_and_concurrent(self, tmp_path):
        out = tmp_path / "bench"
        result = run_benchmark(FIXTURE, out, twice=True)
        assert (out / "cantina_bench_run1.json").is_file()
        assert (out / "cantina_bench_run2.json").is_file()
        assert (out / "cantina_bench_delta.txt").is_file()
        assert (out / "cantina_bench_concurrent.json").is_file()
        m1 = result["run1"]["metrics"]
        m2 = result["run2"]["metrics"]
        assert "duration_ms" in m1 and "tools_run" in m1
        assert "duration_ms" in m2 and "tools_skipped" in m2
        detail = result["concurrent_detail"]
        assert detail["ok"] >= 2
        assert detail["errors"] >= 1

    def test_concurrent_sim_entry(self, tmp_path):
        from cantina import load_scan_ports

        ports = load_scan_ports(FIXTURE / "quick.nmap")
        conc = run_concurrent_recon_simulation(ports, tmp_path / "sim")
        assert conc["ok"] >= 2
        assert conc["errors"] >= 1
        assert len(conc["decision_log"]) >= 2
