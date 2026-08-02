"""Cantina plugin: telnet_enum — banner grab (enum only, no auto-login)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, tool_exists, run_cmd, finding, write_summary, nmap_scripts  # noqa: E402

PLUGIN = {
    "name": "telnet_enum",
    "services": ["telnet"],
    "ports": [23],
    "enabled": True,
    "replaces_builtin": True,
    "description": "Telnet banner / nmap info",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"telnet"}, {23})

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts, notes = [], []
    ofile = pdir / "nmap_telnet.txt"
    content = nmap_scripts(ctx, int(ctx.port), "telnet-ntlm-info,banner", ofile)
    if content:
        arts.append(str(ofile))
        notes.append("nmap_banner")
    else:
        out, _, _ = run_cmd(
            ctx,
            f"timeout 3 bash -c 'echo | nc -nvw 2 {ctx.target} {ctx.port} 2>&1' | head -10",
            8,
        )
        if out:
            ofile = pdir / "telnet_banner.txt"
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            notes.append("nc_banner")
    finding(ctx, "INFO", "Telnet", f"Telnet open on port {ctx.port}")
    notes.append("no_auto_login")
    return write_summary(ctx, "telnet_enum", notes, arts)
