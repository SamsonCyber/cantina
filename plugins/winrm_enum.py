"""
Cantina plugin: winrm_enum (replaces built-in winrm recon).
Enumeration only — hints only for evil-winrm (no auto auth).
"""
from __future__ import annotations
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "winrm_enum",
    "services": ["winrm"],
    "ports": [5985, 5986],
    "enabled": True,
    "replaces_builtin": True,
    "description": "WinRM open-port enum notes",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"winrm", "wsman"}, {5985, 5986})

def run(ctx):
    finding(ctx, "INFO", "WinRM", f"WinRM open on port {ctx.port}")
    return write_summary(ctx, "winrm_enum", [
        f"hint=evil-winrm -i {ctx.target} -u USER -p PASS",
        f"hint=evil-winrm -i {ctx.target} -u USER -H HASH",
        "enum_only",
    ])
