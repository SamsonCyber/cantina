"""Cantina plugin: ldap_enum — anonymous base DN probe (enum only)."""
from __future__ import annotations
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, tool_exists, run_cmd, finding, write_summary  # noqa: E402

PLUGIN = {
    "name": "ldap_enum",
    "services": ["ldap"],
    "ports": [389, 636, 3268, 3269],
    "enabled": True,
    "replaces_builtin": True,
    "description": "LDAP anonymous namingContexts probe",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"ldap", "ldaps"}, {389, 636, 3268, 3269})

def run(ctx):
    target, port = ctx.target, int(ctx.port)
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts, notes = [], [f"hint=ackbar -d DOMAIN -u USER -p PASS -dc {target}"]
    if tool_exists("ldapsearch"):
        out, _, _ = run_cmd(
            ctx,
            f"ldapsearch -x -H ldap://{target}:{port} -b '' -s base namingContexts 2>/dev/null",
            15,
        )
        if out and "namingContexts" in out:
            ofile = pdir / "ldap_anonymous.txt"
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            notes.append("base_dn_found")
            m = re.search(r"namingContexts:\\s*(.+)", out)
            if m:
                base = m.group(1).strip()
                notes.append(f"base={base}")
                anon, _, _ = run_cmd(
                    ctx,
                    f"ldapsearch -x -H ldap://{target}:{port} -b '{base}' '(objectClass=*)' 2>/dev/null | head -100",
                    30,
                )
                if anon and "numEntries" not in anon:
                    pass
                elif anon:
                    finding(ctx, "WARNING", "LDAP", "Anonymous LDAP bind returns data",
                            f"ldapsearch -x -H ldap://{target}:{port} -b '{base}'")
                    notes.append("anon_data")
    notes.append("enum_only")
    return write_summary(ctx, "ldap_enum", notes, arts)
