"""Cantina plugin: elasticsearch_enum — unauth cluster probe (enum only, no write)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, run_cmd, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "elasticsearch_enum",
    "services": ["elasticsearch"],
    "ports": [9200, 9300],
    "enabled": True,
    "replaces_builtin": True,
    "description": "Elasticsearch unauth REST probe",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"elasticsearch", "elastic"}, {9200, 9300})

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    base = f"http://{ctx.target}:{ctx.port}"
    arts, notes = [], []
    for path, label in [("/", "root"), ("/_cat/indices?v", "indices"),
                        ("/_cluster/health?pretty", "health")]:
        out, _, _ = run_cmd(ctx, f"curl -sk --max-time 8 '{base}{path}' 2>/dev/null", 12)
        if out:
            ofile = pdir / f"es_{label}.txt"
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            if label == "root" and "cluster_name" in out:
                finding(ctx, "WARNING", "Elasticsearch", f"Elasticsearch API open on port {ctx.port}")
                notes.append("api_open")
            if label == "indices" and ("index" in out.lower() or "green" in out.lower()):
                finding(ctx, "WARNING", "Elasticsearch", f"ES indices listed unauth on {ctx.port}",
                        f"curl -s '{base}/_cat/indices?v'")
                notes.append("indices_listed")
    notes.append("enum_only_no_write")
    return write_summary(ctx, "elasticsearch_enum", notes, arts)
