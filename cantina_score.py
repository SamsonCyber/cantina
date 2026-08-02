#!/usr/bin/env python3
"""
Cantina scan scorecard — pure metrics over structured port/findings data.

Drives the same dict shape cantina.tcp_ports / parse_nmap_ports produce.
Offline-safe: no nmap, no network. Used by cantina_bench.py and unit tests.

Metrics (all numeric):
  ports_found       open ports extracted
  services_named    ports with a real service name (not empty/unknown/?)
  versions_filled   ports with a non-empty version string
  findings_count    structured findings (e.g. jedi tags)
  completeness      0–100 composite of coverage + metadata fill
  duration_ms       wall time for the scored path (speed)
  tools_run         decision-branch tools selected to run
  tools_skipped     decision-branch tools skipped
  tool_efficiency   0–100 tools_run / (tools_run + tools_skipped)
  services_recon    services that produced a decision record
  worker_errors     concurrent worker failures (isolated)

Legal: scoring only. No exploitation.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

UNKNOWN_SERVICES = frozenset({"", "unknown", "?", "tcpwrapped"})


def _iter_ports(ports: Dict[Any, dict]) -> Iterable[dict]:
    for p, rec in (ports or {}).items():
        if not isinstance(rec, dict):
            continue
        out = dict(rec)
        out.setdefault("port", int(p) if str(p).isdigit() else p)
        yield out


def score_ports(ports: Dict[Any, dict]) -> Dict[str, float]:
    """Score a ports dict (port -> {port, proto, service, version})."""
    records = list(_iter_ports(ports))
    ports_found = float(len(records))
    services_named = 0.0
    versions_filled = 0.0
    for rec in records:
        svc = (rec.get("service") or "").strip().lower()
        ver = (rec.get("version") or "").strip()
        if svc and svc not in UNKNOWN_SERVICES:
            services_named += 1.0
        if ver and ver not in ("?",):
            versions_filled += 1.0

    # Completeness: port presence is baseline; metadata fill scales the rest.
    # Empty corpus scores 0. With ports, weight named services + versions.
    if ports_found <= 0:
        completeness = 0.0
    else:
        named_ratio = services_named / ports_found
        ver_ratio = versions_filled / ports_found
        completeness = round(40.0 + 40.0 * named_ratio + 20.0 * ver_ratio, 2)

    return {
        "ports_found": ports_found,
        "services_named": services_named,
        "versions_filled": versions_filled,
        "completeness": completeness,
    }


def score_findings(findings: Optional[List[dict]]) -> Dict[str, float]:
    """Score findings list (severity/category/message dicts)."""
    findings = findings or []
    # Count non-INFO structured tags as higher-value enum signal
    total = float(len(findings))
    actionable = float(
        sum(
            1
            for f in findings
            if str(f.get("severity", "")).upper()
            in ("LOW", "WARNING", "HIGH", "CRITICAL")
        )
    )
    return {
        "findings_count": total,
        "findings_actionable": actionable,
    }


def score_tool_use(
    decision_log: Optional[List[dict]] = None,
    *,
    worker_errors: Optional[int] = None,
) -> Dict[str, float]:
    """Score decision-branch tool use from decision_log records.

    Each record may have:
      ran: list of tool names
      skipped: list of strings or tool names
      duration_ms: optional per-service wall time
    """
    log = decision_log or []
    tools_run = 0.0
    tools_skipped = 0.0
    services_recon = float(len(log))
    decision_duration_ms = 0.0
    for rec in log:
        if not isinstance(rec, dict):
            continue
        ran = rec.get("ran") or []
        skipped = rec.get("skipped") or []
        tools_run += float(len(ran))
        tools_skipped += float(len(skipped))
        try:
            decision_duration_ms += float(rec.get("duration_ms") or 0)
        except (TypeError, ValueError):
            pass
    total_tools = tools_run + tools_skipped
    if total_tools <= 0:
        tool_efficiency = 0.0
    else:
        tool_efficiency = round(100.0 * tools_run / total_tools, 2)
    out = {
        "tools_run": tools_run,
        "tools_skipped": tools_skipped,
        "tool_efficiency": tool_efficiency,
        "services_recon": services_recon,
        "decision_duration_ms": round(decision_duration_ms, 3),
    }
    if worker_errors is not None:
        out["worker_errors"] = float(worker_errors)
    return out


def score_scan(
    ports: Dict[Any, dict],
    findings: Optional[List[dict]] = None,
    *,
    label: str = "",
    mode: str = "optimized",
    duration_ms: Optional[float] = None,
    decision_log: Optional[List[dict]] = None,
    worker_errors: Optional[int] = None,
    extra: Optional[dict] = None,
) -> Dict[str, Any]:
    """Full score artifact for one scan/parse/recon run.

    Metrics always include coverage, speed (duration_ms), and tool-use when
    decision_log is provided (zeros if absent).
    """
    port_scores = score_ports(ports)
    find_scores = score_findings(findings)
    tool_scores = score_tool_use(decision_log, worker_errors=worker_errors)
    # Composite: completeness + findings bonus + small tool-efficiency bonus
    composite = (
        port_scores["completeness"]
        + min(find_scores["findings_actionable"] * 2.0, 10.0)
        + min(tool_scores["tool_efficiency"] * 0.05, 5.0)
    )
    dur = None if duration_ms is None else round(float(duration_ms), 3)
    metrics = {
        **port_scores,
        **find_scores,
        **tool_scores,
        "composite": round(composite, 2),
        # speed always present as numeric metric (0 if unknown)
        "duration_ms": float(dur if dur is not None else 0.0),
    }
    artifact = {
        "schema": "cantina_score/v2",
        "label": label,
        "mode": mode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": metrics,
        "duration_ms": dur,
        "extra": extra or {},
    }
    return artifact


# Metrics where lower is better (speed / errors) — used for delta verdict
_LOWER_IS_BETTER = frozenset({"duration_ms", "decision_duration_ms", "worker_errors", "tools_skipped"})


def compare_scores(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two score artifacts metric-by-metric.

    Returns improve / regress / flat per metric plus numeric deltas (b - a).
    For duration_ms / worker_errors / tools_skipped, lower is better.
    """
    ma = (a or {}).get("metrics") or {}
    mb = (b or {}).get("metrics") or {}
    keys = sorted(set(ma) | set(mb))
    per_metric = {}
    for k in keys:
        va = float(ma.get(k, 0) or 0)
        vb = float(mb.get(k, 0) or 0)
        delta = round(vb - va, 4)
        if abs(delta) < 1e-9:
            verdict = "flat"
        elif k in _LOWER_IS_BETTER:
            verdict = "improve" if delta < 0 else "regress"
        elif delta > 0:
            verdict = "improve"
        else:
            verdict = "regress"
        per_metric[k] = {"a": va, "b": vb, "delta": delta, "verdict": verdict}
    return {
        "schema": "cantina_score_delta/v1",
        "label_a": (a or {}).get("label"),
        "label_b": (b or {}).get("label"),
        "mode_a": (a or {}).get("mode"),
        "mode_b": (b or {}).get("mode"),
        "metrics": per_metric,
    }


def format_delta_report(delta: Dict[str, Any]) -> str:
    """Human-readable multi-metric delta report."""
    lines = [
        "Cantina score delta",
        f"  A: {delta.get('label_a')} ({delta.get('mode_a')})",
        f"  B: {delta.get('label_b')} ({delta.get('mode_b')})",
        "",
        f"{'metric':<22} {'A':>10} {'B':>10} {'delta':>10} {'verdict':<10}",
        "-" * 66,
    ]
    for name, row in sorted((delta.get("metrics") or {}).items()):
        lines.append(
            f"{name:<22} {row['a']:>10.2f} {row['b']:>10.2f} "
            f"{row['delta']:>+10.2f} {row['verdict']:<10}"
        )
    return "\n".join(lines) + "\n"


def append_history(history_path: Path, score: Dict[str, Any]) -> None:
    """Append one score JSON line to a history JSONL file."""
    history_path = Path(history_path)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    with open(history_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(score, ensure_ascii=False) + "\n")


def write_score(path: Path, score: Dict[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(score, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def timed_call(fn, *args, **kwargs) -> Tuple[Any, float]:
    """Return (result, duration_ms)."""
    t0 = time.perf_counter()
    result = fn(*args, **kwargs)
    ms = (time.perf_counter() - t0) * 1000.0
    return result, ms
