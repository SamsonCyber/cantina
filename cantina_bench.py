#!/usr/bin/env python3
"""
Cantina offline benchmark loop — coverage, speed, and tool-use.

Runs at least twice on the same fixed fixture. Scores:
  (a) coverage  — ports/services/completeness/composite
  (b) speed     — duration_ms (wall time of scored path)
  (c) tool use  — tools_run / tools_skipped from decision records

Also exercises concurrent recon scheduling offline (stub workers) so
tool-use and isolation metrics are real shipped-code paths.

Examples:
  python cantina_bench.py
  python cantina_bench.py --fixture-dir fixtures/cantina_bench -o ./bench_out
  python cantina_bench.py --twice

OSCP-legal: enumeration artifact scoring only.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cantina import (  # noqa: E402
    Scanner,
    decide_ftp_actions,
    decide_http_actions,
    decide_redis_actions,
    decide_smb_actions,
    load_scan_ports,
    parse_http_probe,
    parse_nmap_normal_ports,
    run_tasks_isolated,
)
from cantina_score import (  # noqa: E402
    append_history,
    compare_scores,
    format_delta_report,
    score_scan,
    timed_call,
    write_score,
)

DEFAULT_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cantina_bench"


def _jedi_findings_from_text(nmap_path: Path) -> list:
    """Use Scanner.parse_jedi_findings against a fixture without live scans."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cantina_bench_") as td:
        sc = Scanner("10.10.10.50", td, rate=4, resume=False)
        sc.findings = []
        sc.parse_jedi_findings(nmap_path)
        return list(sc.findings)


def _offline_decisions_from_ports(ports: dict, *, depth: str = "normal") -> list:
    """Build decision_log entries offline from port records + pure decide_*."""
    log = []
    for port, rec in sorted(ports.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else 0):
        p = int(rec.get("port", port))
        svc = (rec.get("service") or "").lower()
        ver = (rec.get("version") or "").lower()
        blob = f"{svc} {ver}"

        if p in (80, 443, 8000, 8080, 3000, 8443) or "http" in svc or "apache" in blob or "nginx" in blob:
            # Synthesize probe signals without network
            if "html" in ver or p in (80, 443, 8080, 3000):
                headers = f"HTTP/1.1 200 OK\r\nServer: {ver or svc or 'http'}\r\nContent-Type: text/html\r\n\r\n"
                body = "<html><title>app</title>" + ("x" * 120)
            else:
                headers = f"HTTP/1.0 200 OK\r\nServer: obscure\r\n\r\n"
                body = "ok"
            signals = parse_http_probe(headers, body)
            actions = decide_http_actions(signals, depth=depth, port=p)
            log.append({
                "svc": "http",
                "port": p,
                "depth": depth,
                "actions": actions,
                "ran": [a["tool"] for a in actions if a.get("run")],
                "skipped": [f"{a['tool']}: {a.get('reason','')}" for a in actions if not a.get("run")],
                "duration_ms": 5.0 + (p % 7),
            })
        elif p in (139, 445) or svc in ("microsoft-ds", "netbios-ssn", "smb"):
            actions = decide_smb_actions(
                null_list_ok=True, shares_readable=False, access_denied=False,
            )
            log.append({
                "svc": "smb",
                "port": p,
                "depth": depth,
                "actions": actions,
                "ran": [a["tool"] for a in actions if a.get("run")],
                "skipped": [f"{a['tool']}: {a.get('reason','')}" for a in actions if not a.get("run")],
                "duration_ms": 12.0,
            })
        elif p == 21 or svc == "ftp":
            actions = decide_ftp_actions(anon_allowed=True, has_version=bool(ver))
            log.append({
                "svc": "ftp",
                "port": p,
                "depth": depth,
                "actions": actions,
                "ran": [a["tool"] for a in actions if a.get("run")],
                "skipped": [f"{a['tool']}: {a.get('reason','')}" for a in actions if not a.get("run")],
                "duration_ms": 8.0,
            })
        elif p == 6379 or svc == "redis":
            actions = decide_redis_actions(pong=True)
            log.append({
                "svc": "redis",
                "port": p,
                "depth": depth,
                "actions": actions,
                "ran": [a["tool"] for a in actions if a.get("run")],
                "skipped": [f"{a['tool']}: {a.get('reason','')}" for a in actions if not a.get("run")],
                "duration_ms": 3.0,
            })
    return log


def run_concurrent_recon_simulation(ports: dict, outdir: Path) -> dict:
    """Drive real Scanner.build_recon_tasks + run_tasks_isolated / concurrent path.

    Stubs _recon_dispatch so no live network; still uses shipped concurrency +
    decision logging. Proves multi-service parallel completion + error isolation.
    """
    sc = Scanner("10.10.10.50", str(outdir), rate=4, resume=False)
    sc.tcp_ports = dict(ports)
    sc.udp_ports = {}
    sc.recon_depth = "normal"
    sc.recon_workers = 4

    # Inject ports that create multiple independent tasks when fixture is thin
    if len(sc.build_recon_tasks()) < 2:
        sc.tcp_ports = {
            22: {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH"},
            80: {"port": 80, "proto": "tcp", "service": "http", "version": "nginx"},
            445: {"port": 445, "proto": "tcp", "service": "microsoft-ds", "version": ""},
            3306: {"port": 3306, "proto": "tcp", "service": "mysql", "version": "5.7"},
        }

    tasks = sc.build_recon_tasks()
    assert len(tasks) >= 2, f"need ≥2 independent tasks, got {tasks}"

    # One intentional failing service type for isolation proof
    fail_task = ("__bench_fail__", 1, None)
    all_tasks = list(tasks) + [fail_task]
    called = []
    lock = sc._state_lock

    def stub_dispatch(svc_type, port, extra):
        if svc_type == "__bench_fail__":
            raise RuntimeError("intentional worker failure for isolation test")
        with lock:
            called.append((svc_type, port))
        # Record a real decision via shipped _log_decision
        if svc_type == "http":
            actions = decide_http_actions(
                parse_http_probe(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
                    "<html>" + ("z" * 100),
                ),
                depth="normal",
                port=port,
            )
        elif svc_type == "smb":
            actions = decide_smb_actions(
                null_list_ok=False, shares_readable=False, access_denied=True,
            )
        elif svc_type == "ftp":
            actions = decide_ftp_actions(anon_allowed=False, has_version=True)
        else:
            actions = [{
                "tool": f"{svc_type}_probe",
                "run": True,
                "reason": "offline stub light probe",
                "weight": "light",
            }]
        sc._log_decision(svc_type, port, actions, duration_ms=1.5)

    sc._recon_dispatch = stub_dispatch  # type: ignore[method-assign]

    t0 = time.perf_counter()
    results = sc.run_recon_concurrent(all_tasks, max_workers=4)
    wall_ms = (time.perf_counter() - t0) * 1000.0

    ok = [r for r in results if r.get("ok")]
    bad = [r for r in results if not r.get("ok")]
    return {
        "tasks": len(all_tasks),
        "ok": len(ok),
        "errors": len(bad),
        "called": list(called),
        "decision_log": list(sc.decision_log),
        "recon_errors": list(sc.recon_errors),
        "duration_ms": round(wall_ms, 3),
        "results": results,
    }


def score_fixture(fixture_dir: Path, *, mode: str, label: str) -> dict:
    """Score one fixture directory (coverage + speed + tool-use).

    mode:
      legacy    — text-only parse of quick.nmap (no XML merge)
      optimized — load_scan_ports (nmap + sibling XML merge)
    """
    fixture_dir = Path(fixture_dir)
    nmap_file = fixture_dir / "quick.nmap"
    if not nmap_file.exists():
        raise FileNotFoundError(f"missing fixture: {nmap_file}")

    t0 = time.perf_counter()
    if mode == "legacy":
        ports, parse_ms = timed_call(parse_nmap_normal_ports, nmap_file)
    elif mode == "optimized":
        ports, parse_ms = timed_call(load_scan_ports, nmap_file)
    else:
        raise ValueError(f"unknown mode: {mode}")

    findings = _jedi_findings_from_text(nmap_file)
    decisions = _offline_decisions_from_ports(ports, depth="normal")
    total_ms = (time.perf_counter() - t0) * 1000.0

    return score_scan(
        ports,
        findings,
        label=label,
        mode=mode,
        duration_ms=round(total_ms, 3),
        decision_log=decisions,
        worker_errors=0,
        extra={
            "fixture": str(fixture_dir),
            "ports": sorted(int(p) for p in ports.keys()),
            "parse_ms": round(parse_ms, 3),
        },
    )


def run_benchmark(
    fixture_dir: Path,
    out_dir: Path,
    *,
    twice: bool = True,
) -> dict:
    """Produce score files + delta report under out_dir (full loop)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    history = out_dir / "score_history.jsonl"

    legacy = score_fixture(fixture_dir, mode="legacy", label="run_legacy")
    opt1 = score_fixture(fixture_dir, mode="optimized", label="run1_optimized")
    write_score(out_dir / "cantina_bench_run1.json", opt1)
    append_history(history, opt1)

    if twice:
        opt2 = score_fixture(fixture_dir, mode="optimized", label="run2_optimized")
        write_score(out_dir / "cantina_bench_run2.json", opt2)
        append_history(history, opt2)
        consec = compare_scores(opt1, opt2)
    else:
        opt2 = opt1
        consec = compare_scores(opt1, opt1)

    improve = compare_scores(legacy, opt1)
    write_score(out_dir / "cantina_bench_legacy.json", legacy)
    write_score(out_dir / "cantina_bench_delta_legacy_vs_opt.json", improve)
    write_score(out_dir / "cantina_bench_delta_run1_vs_run2.json", consec)

    # Concurrent recon simulation (shipped isolation path)
    conc = run_concurrent_recon_simulation(
        load_scan_ports(Path(fixture_dir) / "quick.nmap"),
        out_dir / "concurrent_sim",
    )
    conc_score = score_scan(
        load_scan_ports(Path(fixture_dir) / "quick.nmap"),
        [],
        label="concurrent_sim",
        mode="concurrent",
        duration_ms=conc["duration_ms"],
        decision_log=conc["decision_log"],
        worker_errors=conc["errors"],
        extra={
            "ok": conc["ok"],
            "tasks": conc["tasks"],
            "called": conc["called"],
        },
    )
    write_score(out_dir / "cantina_bench_concurrent.json", conc_score)
    (out_dir / "cantina_concurrent.json").write_text(
        json.dumps({
            "ok": conc["ok"],
            "errors": conc["errors"],
            "tasks": conc["tasks"],
            "called": conc["called"],
            "recon_errors": conc["recon_errors"],
            "duration_ms": conc["duration_ms"],
        }, indent=2),
        encoding="utf-8",
    )

    report = []
    report.append("=== Legacy (text-only) vs Optimized (XML merge) ===\n")
    report.append(format_delta_report(improve))
    report.append("\n=== Consecutive optimized runs (reproducibility) ===\n")
    report.append(format_delta_report(consec))
    report.append("\n=== Concurrent recon sim ===\n")
    report.append(
        f"tasks={conc['tasks']} ok={conc['ok']} errors={conc['errors']} "
        f"duration_ms={conc['duration_ms']} tools_run="
        f"{conc_score['metrics'].get('tools_run')} "
        f"tools_skipped={conc_score['metrics'].get('tools_skipped')}\n"
    )
    # Assert required metric families present
    for name, sc in (("run1", opt1), ("run2", opt2)):
        m = sc["metrics"]
        for key in ("composite", "duration_ms", "tools_run", "tools_skipped"):
            if key not in m:
                raise AssertionError(f"{name} missing metric {key}")
    report_text = "".join(report)
    (out_dir / "cantina_bench_delta.txt").write_text(report_text, encoding="utf-8")

    return {
        "legacy": legacy,
        "run1": opt1,
        "run2": opt2,
        "delta_legacy_vs_opt": improve,
        "delta_run1_vs_run2": consec,
        "concurrent": conc_score,
        "concurrent_detail": conc,
        "report": report_text,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Cantina offline bench loop (coverage + speed + tool-use)"
    )
    p.add_argument(
        "--fixture-dir",
        type=Path,
        default=DEFAULT_FIXTURE,
        help="Directory with quick.nmap (+ optional quick.xml)",
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("cantina_bench_out"),
        help="Output directory for score JSON + delta",
    )
    p.add_argument(
        "--twice",
        action="store_true",
        default=True,
        help="Run optimized path twice for reproducibility delta (default on)",
    )
    p.add_argument(
        "--once",
        action="store_true",
        help="Only one optimized run (still writes legacy comparison)",
    )
    args = p.parse_args(argv)
    twice = not args.once

    try:
        result = run_benchmark(args.fixture_dir, args.output, twice=twice)
    except Exception as e:
        print(f"[-] bench failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print(result["report"])
    print(f"[+] Scores: {args.output}")

    # Gate: concurrent isolation must leave siblings OK
    detail = result.get("concurrent_detail") or {}
    if detail.get("ok", 0) < 2:
        print("[-] concurrent sim: expected ≥2 successful workers", file=sys.stderr)
        return 3
    if detail.get("errors", 0) < 1:
        print("[-] concurrent sim: expected isolated failure", file=sys.stderr)
        return 3

    metrics = result["delta_legacy_vs_opt"]["metrics"]
    comp = metrics.get("composite", {})
    if comp.get("verdict") == "regress":
        print("[!] composite regressed vs legacy", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
