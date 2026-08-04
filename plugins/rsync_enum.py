"""Cantina plugin: rsync_enum — module list (enum only)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, run_cmd, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "rsync_enum",
    "services": ["rsync"],
    "ports": [873],
    "enabled": True,
    "replaces_builtin": True,
    "description": "rsync module listing",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"rsync"}, {873})

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    ofile = pdir / f"rsync_{ctx.port}.txt"
    out, _, _ = run_cmd(ctx, f"rsync -av --list-only rsync://{ctx.target}:{ctx.port}/", 30)
    arts = []
    notes = []
    if out:
        ofile.write_text(out, encoding="utf-8")
        arts.append(str(ofile))
        finding(ctx, "WARNING", "rsync", f"rsync on port {ctx.port} lists modules",
                f"rsync -av rsync://{ctx.target}:{ctx.port}/MODULE ./loot/")
        notes.append("modules_listed")
    else:
        finding(ctx, "INFO", "rsync", f"rsync on port {ctx.port}")
        notes.append("no_modules_or_auth")
    return write_summary(ctx, "rsync_enum", notes, arts)
