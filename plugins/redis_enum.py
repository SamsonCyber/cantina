"""Cantina plugin: redis_enum — unauth PING/INFO only (no redis-brute)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, tool_exists, run_cmd, finding, write_summary, nmap_scripts  # noqa: E402

PLUGIN = {
    "name": "redis_enum",
    "services": ["redis"],
    "ports": [6379],
    "enabled": True,
    "replaces_builtin": True,
    "description": "Redis unauth PING/INFO (no brute)",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"redis"}, {6379})

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts, notes = [], []
    pong = False
    if tool_exists("redis-cli"):
        out, _, _ = run_cmd(ctx, f"redis-cli -h {ctx.target} -p {ctx.port} --raw PING 2>/dev/null", 8)
        pong = (out or "").strip().upper() == "PONG"
        notes.append(f"pong={pong}")
        if pong:
            info_out, _, _ = run_cmd(ctx, f"redis-cli -h {ctx.target} -p {ctx.port} INFO 2>/dev/null", 15)
            if info_out:
                ofile = pdir / "redis_info.txt"
                ofile.write_text(info_out, encoding="utf-8")
                arts.append(str(ofile))
            finding(ctx, "CRITICAL", "Redis",
                    f"Redis on port {ctx.port} allows unauthenticated access",
                    f"redis-cli -h {ctx.target} -p {ctx.port}")
    ofile = pdir / "redis_nmap.txt"
    content = nmap_scripts(ctx, int(ctx.port), "redis-info", ofile)
    if content:
        arts.append(str(ofile))
        if "redis_version" in content.lower():
            notes.append("nmap_redis_info")
    notes.append("no_auto_brute")
    return write_summary(ctx, "redis_enum", notes, arts)
