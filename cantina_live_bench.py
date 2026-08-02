#!/usr/bin/env python3
"""
Cantina live lab benchmark — score a real scan outdir against lab ground truth.

OSCP-legal: compares enumeration coverage only (ports/services found vs expected).
Does not run exploits or credential sprays.

Examples:
  python3 cantina_live_bench.py -o ~/cantina-live/192.168.1.206
  python3 cantina_live_bench.py -o ./cantina/192.168.1.206 \\
      --expected lab/cantina_lab_expected.json

Outputs score JSON + delta vs previous score_history.jsonl if present.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cantina import load_scan_ports, parse_nmap_ports  # noqa: E402
from cantina_score import (  # noqa: E402
    append_history,
    compare_scores,
    format_delta_report,
    score_scan,
    write_score,
)

DEFAULT_EXPECTED = Path(__file__).resolve().parent / "lab" / "cantina_lab_expected.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _ports_from_outdir(outdir: Path) -> Dict[Any, dict]:
    """Merge all nmap artifacts under outdir/nmap (and top-level) into one ports dict."""
    candidates = []
    nmap_dir = outdir / "nmap"
    if nmap_dir.is_dir():
        candidates.extend(sorted(nmap_dir.glob("*.nmap")))
        candidates.extend(sorted(nmap_dir.glob("*.xml")))
    candidates.extend(sorted(outdir.glob("*.nmap")))
    candidates.extend(sorted(outdir.glob("*.xml")))

    merged: Dict[Any, dict] = {}
    for path in candidates:
        try:
            if path.suffix == ".xml" or path.name.endswith(".xml"):
                from cantina import parse_nmap_xml_ports

                ports = parse_nmap_xml_ports(path)
            else:
                # Prefer sibling-aware load when both -oN and -oX exist
                ports = load_scan_ports(path) if path.suffix == ".nmap" else parse_nmap_ports(path)
            for k, v in (ports or {}).items():
                if k not in merged:
                    merged[k] = v
                else:
                    # Prefer richer service/version
                    old = merged[k]
                    if not (old.get("service") or "").strip() and (v.get("service") or "").strip():
                        old["service"] = v["service"]
                    if not (old.get("version") or "").strip() and (v.get("version") or "").strip():
                        old["version"] = v["version"]
        except Exception as e:
            print(f"[!] skip {path.name}: {e}", file=sys.stderr)
    return merged


def _findings_from_json(outdir: Path) -> list:
    cj = outdir / "cantina.json"
    if not cj.exists():
        return []
    try:
        data = _load_json(cj)
        return list(data.get("findings") or [])
    except Exception:
        return []


def coverage_against_expected(
    found_ports: Dict[Any, dict],
    expected: dict,
) -> Dict[str, Any]:
    """Compute recall/weighted coverage vs ground-truth expected ports."""
    tcp_exp = expected.get("tcp_expected") or {}
    udp_exp = expected.get("udp_expected") or {}
    weights = expected.get("score_weights") or {}
    w_common = float(weights.get("common_tcp", 1.0))
    w_uncommon = float(weights.get("uncommon_tcp", 1.5))
    w_obscure = float(weights.get("obscure_tcp", 2.0))
    w_udp = float(weights.get("udp", 1.5))

    found_nums: Set[int] = set()
    for k, rec in (found_ports or {}).items():
        try:
            found_nums.add(int(rec.get("port", k)))
        except (TypeError, ValueError):
            continue

    def tier_weight(tier: str, is_udp: bool = False) -> float:
        if is_udp:
            return w_udp
        t = (tier or "common").lower()
        if t == "obscure":
            return w_obscure
        if t == "uncommon":
            return w_uncommon
        return w_common

    hit_tcp = []
    miss_tcp = []
    hit_obscure = []
    miss_obscure = []
    weight_hit = 0.0
    weight_total = 0.0

    for port_s, meta in tcp_exp.items():
        port = int(port_s)
        tier = (meta or {}).get("tier", "common")
        w = tier_weight(tier, False)
        weight_total += w
        if port in found_nums:
            hit_tcp.append(port)
            weight_hit += w
            if tier == "obscure":
                hit_obscure.append(port)
        else:
            miss_tcp.append(port)
            if tier == "obscure":
                miss_obscure.append(port)

    hit_udp = []
    miss_udp = []
    for port_s, meta in udp_exp.items():
        port = int(port_s)
        tier = (meta or {}).get("tier", "common")
        w = tier_weight(tier, True)
        weight_total += w
        if port in found_nums:
            hit_udp.append(port)
            weight_hit += w
        else:
            miss_udp.append(port)

    n_tcp = len(tcp_exp) or 1
    n_obscure = sum(1 for m in tcp_exp.values() if (m or {}).get("tier") == "obscure") or 1
    n_udp = len(udp_exp) or 1

    recall_tcp = len(hit_tcp) / n_tcp
    recall_obscure = len(hit_obscure) / n_obscure
    recall_udp = len(hit_udp) / n_udp if udp_exp else 0.0
    weighted = (weight_hit / weight_total) if weight_total else 0.0

    return {
        "found_port_count": len(found_nums),
        "found_ports": sorted(found_nums),
        "tcp_hit": sorted(hit_tcp),
        "tcp_miss": sorted(miss_tcp),
        "udp_hit": sorted(hit_udp),
        "udp_miss": sorted(miss_udp),
        "obscure_hit": sorted(hit_obscure),
        "obscure_miss": sorted(miss_obscure),
        "recall_tcp": round(recall_tcp, 4),
        "recall_obscure": round(recall_obscure, 4),
        "recall_udp": round(recall_udp, 4),
        "weighted_coverage": round(weighted * 100.0, 2),
        "expected_tcp_count": len(tcp_exp),
        "expected_obscure_count": sum(
            1 for m in tcp_exp.values() if (m or {}).get("tier") == "obscure"
        ),
        "expected_udp_count": len(udp_exp),
    }


def score_live_outdir(outdir: Path, expected_path: Path) -> dict:
    outdir = Path(outdir)
    expected = _load_json(expected_path)
    ports = _ports_from_outdir(outdir)
    findings = _findings_from_json(outdir)
    base = score_scan(
        ports,
        findings,
        label="live_lab",
        mode="live",
        extra={"outdir": str(outdir), "target": expected.get("target")},
    )
    cov = coverage_against_expected(ports, expected)
    # Blend: cantina completeness + weighted ground-truth coverage
    base["metrics"]["lab_recall_tcp"] = cov["recall_tcp"] * 100.0
    base["metrics"]["lab_recall_obscure"] = cov["recall_obscure"] * 100.0
    base["metrics"]["lab_recall_udp"] = cov["recall_udp"] * 100.0
    base["metrics"]["lab_weighted_coverage"] = cov["weighted_coverage"]
    base["metrics"]["composite"] = round(
        0.4 * base["metrics"].get("completeness", 0)
        + 0.4 * cov["weighted_coverage"]
        + 0.2 * (cov["recall_obscure"] * 100.0),
        2,
    )
    base["lab_coverage"] = cov
    base["expected_file"] = str(expected_path)
    return base


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Cantina live lab ground-truth scorecard")
    p.add_argument("-o", "--outdir", type=Path, required=True, help="Scan output directory")
    p.add_argument(
        "--expected",
        type=Path,
        default=DEFAULT_EXPECTED,
        help="Ground-truth JSON (default: lab/cantina_lab_expected.json)",
    )
    p.add_argument(
        "--history",
        type=Path,
        default=None,
        help="score_history.jsonl path (default: OUTDIR/score_history.jsonl)",
    )
    args = p.parse_args(argv)

    if not args.outdir.is_dir():
        print(f"[-] outdir not found: {args.outdir}", file=sys.stderr)
        return 1
    if not args.expected.is_file():
        print(f"[-] expected file missing: {args.expected}", file=sys.stderr)
        return 1

    score = score_live_outdir(args.outdir, args.expected)
    score_path = args.outdir / "cantina_live_score.json"
    write_score(score_path, score)
    history = args.history or (args.outdir / "score_history.jsonl")
    prev = None
    if history.exists():
        try:
            lines = [ln for ln in history.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                prev = json.loads(lines[-1])
        except Exception:
            prev = None
    append_history(history, score)

    print("=== Cantina live lab score ===")
    m = score["metrics"]
    for k in (
        "ports_found",
        "services_named",
        "versions_filled",
        "completeness",
        "lab_recall_tcp",
        "lab_recall_obscure",
        "lab_recall_udp",
        "lab_weighted_coverage",
        "composite",
    ):
        if k in m:
            print(f"  {k}: {m[k]}")
    cov = score["lab_coverage"]
    print(f"  tcp hit/miss: {cov['tcp_hit']} / miss {cov['tcp_miss']}")
    print(f"  obscure hit/miss: {cov['obscure_hit']} / miss {cov['obscure_miss']}")
    print(f"  udp hit/miss: {cov['udp_hit']} / miss {cov['udp_miss']}")
    print(f"[+] Wrote {score_path}")

    if prev and "metrics" in prev:
        delta = compare_scores(prev, score)
        report = format_delta_report(delta)
        (args.outdir / "cantina_live_delta.txt").write_text(report, encoding="utf-8")
        print("\n=== vs previous history entry ===")
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
