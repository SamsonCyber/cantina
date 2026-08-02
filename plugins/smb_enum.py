"""
Cantina plugin: smb_enum (replaces built-in SMB recon).
Null session probe + smbmap/enum4linux-ng + safe nmap SMB scripts (no ms08-067 exploit delivery).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import (  # noqa: E402
    match_service, tool_exists, run_cmd, finding, write_summary,
)

PLUGIN = {
    "name": "smb_enum",
    "services": ["smb"],
    "ports": [139, 445],
    "enabled": True,
    "replaces_builtin": True,
    "description": "SMB null session / enum4linux-ng / safe nmap scripts",
    "priority": 40,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}


def match(signals):
    return match_service(
        signals, {"smb", "microsoft-ds", "netbios-ssn"}, {139, 445},
    )


def run(ctx):
    target = ctx.target
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts = []
    notes = []
    null_ok = False
    access_denied = False

    if tool_exists("smbclient"):
        out, _, _ = run_cmd(ctx, f"smbclient -L //{target} -N 2>/dev/null", 15)
        ofile = pdir / "smbclient_null.txt"
        if out:
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            access_denied = "NT_STATUS_ACCESS_DENIED" in out
            null_ok = (not access_denied) and (
                "Disk" in out or "Sharename" in out or "IPC" in out
            )
            if null_ok:
                finding(ctx, "WARNING", "SMB", "Null session SMB listing allowed",
                        f"smbclient -L //{target} -N")
                notes.append("null_session_ok")

    try:
        from cantina import decide_smb_actions, actions_to_run, select_smb_enum_tool
    except ImportError:
        decide_smb_actions = None
        actions_to_run = None
        select_smb_enum_tool = None

    want = set()
    if decide_smb_actions and actions_to_run:
        actions = decide_smb_actions(
            null_list_ok=null_ok, shares_readable=False, access_denied=access_denied,
        )
        if callable(ctx.log_decision):
            try:
                ctx.log_decision("smb", int(ctx.port), actions, extra={"plugin": "smb_enum"})
            except Exception:
                pass
        want = {a["tool"] for a in actions_to_run(actions)}
    else:
        want = {"smbmap", "enum4linux", "nmap_smb_scripts"}

    if "smbmap" in want and tool_exists("smbmap"):
        ofile = pdir / "smbmap_null.txt"
        out, _, _ = run_cmd(ctx, f"smbmap -H {target} --no-banner 2>/dev/null", 15)
        if out:
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            notes.append("smbmap")

    if "enum4linux" in want:
        avail = set()
        if tool_exists("enum4linux-ng"):
            avail.add("enum4linux-ng")
        if tool_exists("enum4linux"):
            avail.add("enum4linux")
        tool = select_smb_enum_tool(avail) if select_smb_enum_tool else (
            "enum4linux-ng" if "enum4linux-ng" in avail else ("enum4linux" if "enum4linux" in avail else None)
        )
        if tool:
            ofile = pdir / f"{tool.replace('-', '_')}.txt"
            cmd = f"{tool} -A {target} 2>/dev/null" if tool == "enum4linux-ng" else f"{tool} -a {target} 2>/dev/null"
            out, _, _ = run_cmd(ctx, cmd, 120)
            if out:
                ofile.write_text(out, encoding="utf-8")
                arts.append(str(ofile))
                notes.append(tool)

    if "nmap_smb_scripts" in want and tool_exists("nmap"):
        ofile = pdir / "nmap_smb.txt"
        scripts = (
            "smb-enum-shares,smb-enum-users,smb-os-discovery,"
            "smb-vuln-ms17-010,smb-vuln-cve-2020-0796,smb-protocols,smb-security-mode"
        )
        ping = (ctx.extra or {}).get("ping_flag") or ""
        run_cmd(
            ctx,
            f"nmap {ping} -p 139,445 --script '{scripts}' -oN {ofile} {target} 2>/dev/null",
            120,
        )
        if ofile.exists():
            arts.append(str(ofile))
            content = ofile.read_text(errors="replace")
            if "VULNERABLE" in content:
                finding(ctx, "CRITICAL", "SMB", "SMB vulnerability detected", f"Check {ofile}")
                notes.append("smb_vuln")

    return write_summary(ctx, "smb_enum", notes or ["enum_only"], arts)
