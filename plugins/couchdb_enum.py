"""Cantina plugin: couchdb_enum — REST unauth probe (enum only)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, run_cmd, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "couchdb_enum",
    "services": ["couchdb"],
    "ports": [5984],
    "enabled": True,
    "replaces_builtin": True,
    "description": "CouchDB REST unauth probe",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"couchdb"}, {5984})

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    notes, arts = [], []
    out, _, _ = run_cmd(ctx, f"curl -s http://{ctx.target}:{ctx.port}/", 15)
    if out and ("couchdb" in out.lower() or "welcome" in out.lower()):
        finding(ctx, "WARNING", "CouchDB", f"CouchDB REST API accessible on port {ctx.port}")
        notes.append("api_open")
        dbs, _, _ = run_cmd(ctx, f"curl -s http://{ctx.target}:{ctx.port}/_all_dbs", 15)
        if dbs and dbs.startswith("["):
            ofile = pdir / "couchdb_all_dbs.txt"
            ofile.write_text(dbs, encoding="utf-8")
            arts.append(str(ofile))
            finding(ctx, "CRITICAL", "CouchDB",
                    f"CouchDB lists databases unauthenticated: {dbs[:100]}",
                    f"curl http://{ctx.target}:{ctx.port}/_all_dbs")
            notes.append("dbs_listed")
    else:
        finding(ctx, "INFO", "CouchDB", f"CouchDB on port {ctx.port}")
        notes.append("no_unauth")
    return write_summary(ctx, "couchdb_enum", notes, arts)
