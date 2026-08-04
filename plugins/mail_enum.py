"""Cantina plugin: mail_enum — POP3/IMAP capability probes (enum only)."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, nmap_scripts, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "mail_enum",
    "services": ["mail", "pop3", "imap", "pop3s", "imaps"],
    "ports": [110, 143, 993, 995],
    "enabled": True,
    "replaces_builtin": True,
    "description": "POP3/IMAP capabilities / NTLM info",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(
        signals, {"mail", "pop3", "imap", "pop3s", "imaps"}, {110, 143, 993, 995},
    )

def run(ctx):
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    ofile = pdir / f"mail_{ctx.port}_nmap.txt"
    scripts = "pop3-capabilities,pop3-ntlm-info,imap-capabilities,imap-ntlm-info"
    content = nmap_scripts(ctx, int(ctx.port), scripts, ofile)
    arts = [str(ofile)] if content else []
    notes = [f"svc={ctx.service or ctx.svc_type or 'mail'}"]
    if content and "ntlm" in content.lower():
        finding(ctx, "WARNING", "Mail", f"NTLM info leak on mail port {ctx.port}")
        notes.append("ntlm_leak")
    finding(ctx, "INFO", "Mail", f"{ctx.service or 'mail'} on port {ctx.port}")
    notes.append("enum_only")
    return write_summary(ctx, "mail_enum", notes, arts)
