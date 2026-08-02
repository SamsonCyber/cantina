"""Cantina plugin: kerberos_enum — DC notes + kerbrute/AS-REP when tools present (no spray)."""
from __future__ import annotations
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, tool_exists, run_cmd, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "kerberos_enum",
    "services": ["kerberos"],
    "ports": [88],
    "enabled": True,
    "replaces_builtin": True,
    "description": "Kerberos DC notes / kerbrute when present",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"kerberos"}, {88})

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    notes = ["dc_likely", f"hint=ackbar -d DOMAIN -u USER -p PASS -dc {ctx.target}"]
    finding(ctx, "WARNING", "Kerberos", f"Domain Controller detected (port 88)")
    # Domain from version string if present
    domain = None
    ver = ctx.version or ""
    m = re.search(r"Domain:\\s*([a-zA-Z0-9.-]+)", ver)
    if m:
        domain = m.group(1)
        notes.append(f"domain={domain}")
    if tool_exists("kerbrute") and domain:
        for wl in (
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/wordlists/metasploit/unix_users.txt",
        ):
            if Path(wl).exists():
                ofile = pdir / "kerbrute_users.txt"
                run_cmd(ctx, f"kerbrute userenum -d {domain} --dc {ctx.target} {wl} -o {ofile} 2>/dev/null", 120)
                notes.append("kerbrute_attempted")
                break
    notes.append("enum_only_no_spray")
    return write_summary(ctx, "kerberos_enum", notes)
