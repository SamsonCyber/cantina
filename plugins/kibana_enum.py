"""Cantina plugin: kibana_enum — status probe (enum only)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, run_cmd, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "kibana_enum",
    "services": ["kibana"],
    "ports": [5601],
    "enabled": True,
    "replaces_builtin": True,
    "description": "Kibana status probe",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"kibana"}, {5601})

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts, notes = [], []
    for path, label in [("/", "root"), ("/api/status", "status")]:
        url = f"http://{ctx.target}:{ctx.port}{path}"
        hdr, _, _ = run_cmd(ctx, f"curl -skI --max-time 8 '{url}' 2>/dev/null", 12)
        body, _, _ = run_cmd(ctx, f"curl -sk --max-time 8 '{url}' 2>/dev/null | head -c 1500", 12)
        blob = (hdr or "") + "\n" + (body or "")
        if blob.strip():
            ofile = pdir / f"kibana_{label}.txt"
            ofile.write_text(blob, encoding="utf-8")
            arts.append(str(ofile))
            notes.append(label)
    finding(ctx, "INFO", "Kibana", f"Kibana port {ctx.port} reachable")
    notes.append("enum_only")
    return write_summary(ctx, "kibana_enum", notes, arts)
