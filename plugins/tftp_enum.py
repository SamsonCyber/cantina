"""
Cantina plugin: tftp_enum (replaces built-in tftp recon).
Enumeration only. No exploitation. No credential spray.
"""
from __future__ import annotations
from pathlib import Path
import sys

# Allow import of sibling _plugin_util
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import (  # noqa: E402
    match_service, nmap_scripts, tool_exists, run_cmd, finding, write_summary,
)

PLUGIN = {
    "name": "tftp_enum",
    "services": ['tftp'],
    "ports": [69],
    "enabled": True,
    "replaces_builtin": True,
    "description": "TFTP enum",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

_NAMES = set(['tftp'])
_PORTS = set([69])


def match(signals):
    return match_service(signals, _NAMES, _PORTS)


def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts = []
    notes = []
    scripts = "tftp-enum"
    extra = "-sU"
    ofile = pdir / "nmap_tftp.txt"
    content = ""
    if scripts:
        content = nmap_scripts(ctx, int(ctx.port), scripts, ofile, extra_flags=extra)
        if content:
            arts.append(str(ofile))
            notes.append(f"nmap_bytes={len(content)}")
            low = content.lower()
            if "vulnerable" in low:
                finding(ctx, "CRITICAL", "TFTP", "TFTP vulnerability signal in nmap output")
                notes.append("vulnerable_signal")
            if "empty-password" in low or "empty password" in low:
                finding(ctx, "CRITICAL", "TFTP", "Empty password signal")
                notes.append("empty_password")
            if "dns_computer_name" in low or "dns_domain_name" in low:
                finding(ctx, "INFO", "TFTP", "NTLM/DNS name leak in nmap output")
                notes.append("ntlm_info")
            if "password" in low and "authentication" in low:
                notes.append("auth_methods_seen")
    else:
        notes.append("no_nmap_scripts")
    # Always leave a summary artifact even if tools missing
    notes.append("enum_only")
    return write_summary(ctx, "tftp_enum", notes, arts)
