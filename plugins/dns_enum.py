"""Cantina plugin: dns_enum — zone transfer probes (enum only)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, tool_exists, run_cmd, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "dns_enum",
    "services": ["dns"],
    "ports": [53],
    "enabled": True,
    "replaces_builtin": True,
    "description": "DNS AXFR / dnsrecon enum",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"dns", "domain"}, {53})

def run(ctx):
    target = ctx.target
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts, notes = [], []
    if tool_exists("dnsrecon"):
        ofile = pdir / "dnsrecon.txt"
        out, _, _ = run_cmd(ctx, f"dnsrecon -d {target} -t axfr 2>/dev/null", 30)
        if out:
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            if "Zone Transfer" in out and "unsuccessful" not in out.lower():
                finding(ctx, "CRITICAL", "DNS", "Zone transfer allowed", f"dnsrecon -d {target} -t axfr")
                notes.append("axfr_ok")
    if tool_exists("dig"):
        out, _, _ = run_cmd(ctx, f"dig axfr @{target} 2>/dev/null", 15)
        if out and "AXFR" in out and "Transfer failed" not in out:
            ofile = pdir / "dig_axfr.txt"
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            finding(ctx, "CRITICAL", "DNS", "Zone transfer via dig")
            notes.append("dig_axfr")
    notes.append("enum_only")
    return write_summary(ctx, "dns_enum", notes, arts)
