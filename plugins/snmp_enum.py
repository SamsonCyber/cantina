"""
Cantina plugin: SNMP enum (replaces built-in snmp recon path).

Phases (enumeration only, no snmp-brute spray):
  1. Short common-community probe via snmpwalk
  1b. onesixtyone when available and no community yet
  2. Deep OID walks when community known
  3. snmp-check summary when available
  4. nmap snmp-info scripts (no snmp-brute)

Legal: enumeration-only; OSCP-safe; no exploit/spray auto-run.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

PLUGIN = {
    "name": "snmp_enum",
    "services": ["snmp"],
    "ports": [161, 162],
    "enabled": True,
    "replaces_builtin": True,
    "description": "SNMP community probe + onesixtyone + walks (enum only)",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

_COMMUNITIES = [
    "public", "private", "manager", "community", "snmp",
    "monitor", "admin", "default", "cisco", "switch",
]

_OID_MAP = {
    "sysDescr": "1.3.6.1.2.1.1.1",
    "sysName": "1.3.6.1.2.1.1.5",
    "sysContact": "1.3.6.1.2.1.1.4",
    "sysLocation": "1.3.6.1.2.1.1.6",
    "interfaces": "1.3.6.1.2.1.2.2.1.2",
    "ip_addresses": "1.3.6.1.2.1.4.20.1.1",
    "routes": "1.3.6.1.2.1.4.21.1",
    "tcp_ports": "1.3.6.1.2.1.6.13.1.3",
    "processes": "1.3.6.1.2.1.25.4.2.1.2",
    "software": "1.3.6.1.2.1.25.6.3.1.2",
    "users": "1.3.6.1.4.1.77.1.2.25",
}


def match(signals):
    svc = (signals.get("service") or "").lower()
    svc_type = (signals.get("svc_type") or "").lower()
    port = int(signals.get("port") or 0)
    if svc_type == "snmp" or svc == "snmp":
        return True
    return port in (161, 162)


def _tool_exists(name: str) -> bool:
    return bool(shutil.which(name))


def _run(ctx, cmd: str, timeout: int = 60):
    """Return (stdout, stderr, rc) using ctx.run_cmd when wired."""
    if ctx.run_cmd is None:
        return "", "no run_cmd", 1
    try:
        # cantina.run returns (stdout, stderr, rc)
        out = ctx.run_cmd(cmd, timeout=timeout)
        if isinstance(out, tuple) and len(out) == 3:
            return out[0] or "", out[1] or "", int(out[2] if out[2] is not None else 1)
        if isinstance(out, tuple) and len(out) == 2:
            # run_live style
            return out[0] or "", "", int(out[1] if out[1] is not None else 1)
        return str(out or ""), "", 0
    except TypeError:
        # lambda without timeout kw
        try:
            out = ctx.run_cmd(cmd)
            if isinstance(out, tuple) and len(out) >= 3:
                return out[0] or "", out[1] or "", int(out[2])
            if isinstance(out, tuple) and len(out) == 2:
                return out[0] or "", "", int(out[1])
            return str(out or ""), "", 0
        except Exception as e:
            return "", str(e), 1
    except Exception as e:
        return "", str(e), 1


def _finding(ctx, severity, category, message, exploit_cmd=""):
    if callable(ctx.add_finding):
        try:
            ctx.add_finding(severity, category, message, exploit_cmd=exploit_cmd)
        except TypeError:
            ctx.add_finding(severity, category, message)


def run(ctx):
    """SNMP enum pipeline (same behavior as former built-in)."""
    # Import decision helpers from cantina when available
    try:
        from cantina import decide_snmp_actions, actions_to_run
    except ImportError:
        decide_snmp_actions = None
        actions_to_run = None

    target = ctx.target
    port = int(ctx.port)
    recon_dir = Path(ctx.recon_dir)
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)

    notes = []
    valid_comm = None
    artifacts = []

    # Phase 1: short common-community probe
    if _tool_exists("snmpwalk"):
        for comm in _COMMUNITIES:
            stdout, _, rc = _run(
                ctx,
                f"snmpwalk -v2c -c {comm} {target} 1.3.6.1.2.1.1.1.0 2>/dev/null",
                timeout=10,
            )
            if rc == 0 and stdout and "Timeout" not in stdout and "No Response" not in stdout:
                valid_comm = comm
                notes.append(f"community_valid={comm}")
                _finding(
                    ctx, "CRITICAL", "SNMP",
                    f"SNMP community string: {comm}",
                    f"snmpwalk -v2c -c {comm} {target}",
                )
                break
    else:
        notes.append("snmpwalk_missing")

    o61 = _tool_exists("onesixtyone")
    if decide_snmp_actions:
        actions = decide_snmp_actions(
            valid_community=valid_comm, onesixtyone_available=o61,
        )
        want = {a["tool"] for a in actions_to_run(actions)} if actions_to_run else set()
        if callable(ctx.log_decision):
            try:
                ctx.log_decision(
                    "snmp", port, actions, extra={"community": valid_comm, "plugin": "snmp_enum"},
                )
            except Exception:
                pass
    else:
        want = {"community_probe", "nmap_snmp_info"}
        if o61 and not valid_comm:
            want.add("onesixtyone")
        if valid_comm:
            want.update({"snmpwalk_deep", "snmp_check"})

    # Phase 1b: onesixtyone
    if "onesixtyone" in want and o61 and not valid_comm:
        comm_file = pdir / "snmp_communities_short.txt"
        comm_file.write_text("\n".join(_COMMUNITIES) + "\n", encoding="utf-8")
        ofile = pdir / "onesixtyone.txt"
        cmd = f"onesixtyone -c {comm_file} {target} 2>/dev/null"
        stdout, _, _ = _run(ctx, cmd, timeout=60)
        if stdout:
            ofile.write_text(stdout, encoding="utf-8")
            artifacts.append(str(ofile))
            for line in stdout.splitlines():
                m = re.search(r"\[([^\]]+)\]", line)
                if m:
                    valid_comm = m.group(1).strip()
                    notes.append(f"onesixtyone_community={valid_comm}")
                    _finding(
                        ctx, "CRITICAL", "SNMP",
                        f"SNMP community string: {valid_comm}",
                        f"snmpwalk -v2c -c {valid_comm} {target}",
                    )
                    break
        if decide_snmp_actions and actions_to_run:
            actions = decide_snmp_actions(
                valid_community=valid_comm, onesixtyone_available=o61,
            )
            want = {a["tool"] for a in actions_to_run(actions)}

    # Phase 2: deep walk
    if "snmpwalk_deep" in want and valid_comm and _tool_exists("snmpwalk"):
        full_output = []
        for label, oid in _OID_MAP.items():
            stdout, _, rc = _run(
                ctx,
                f"snmpwalk -v2c -c {valid_comm} {target} {oid} 2>/dev/null",
                timeout=20,
            )
            if rc == 0 and stdout and "No Such" not in stdout:
                full_output.append(f"\n=== {label} ===\n{stdout}")
                if label == "users":
                    users = re.findall(r'STRING:\s*"?(\S+)"?', stdout)
                    if users:
                        _finding(
                            ctx, "WARNING", "SNMP",
                            f"Users enumerated: {', '.join(users[:15])}",
                            f"snmpwalk -v2c -c {valid_comm} {target} {oid}",
                        )
        if full_output:
            ofile = pdir / f"snmpwalk_{valid_comm}_full.txt"
            ofile.write_text("\n".join(full_output), encoding="utf-8")
            artifacts.append(str(ofile))
        ofile = pdir / f"snmpwalk_{valid_comm}_raw.txt"
        stdout, _, _ = _run(
            ctx, f"snmpwalk -v2c -c {valid_comm} {target} 2>/dev/null", timeout=120,
        )
        if stdout:
            ofile.write_text(stdout, encoding="utf-8")
            artifacts.append(str(ofile))

    # Phase 3: snmp-check
    if "snmp_check" in want and valid_comm and _tool_exists("snmp-check"):
        ofile = pdir / "snmp_check.txt"
        stdout, _, _ = _run(ctx, f"snmp-check {target} 2>/dev/null", timeout=60)
        if stdout and "ERROR" not in stdout:
            ofile.write_text(stdout, encoding="utf-8")
            artifacts.append(str(ofile))

    # Phase 4: nmap snmp-info (no snmp-brute)
    if "nmap_snmp_info" in want and _tool_exists("nmap"):
        ofile = pdir / "nmap_snmp.txt"
        cmd = (
            f"nmap -sU -p {port} --script "
            f"'snmp-info,snmp-netstat,snmp-processes,snmp-win32-software,"
            f"snmp-interfaces,snmp-sysdescr' -oN {ofile} {target} 2>/dev/null"
        )
        _run(ctx, cmd, timeout=90)
        if ofile.exists():
            artifacts.append(str(ofile))

    summary = pdir / "plugin_snmp_enum.txt"
    summary.write_text(
        "# snmp_enum plugin (enumeration only)\n"
        f"target={target}\nport={port}\n"
        f"community={valid_comm or ''}\n"
        f"notes={'; '.join(notes)}\n"
        f"artifacts={len(artifacts)}\n",
        encoding="utf-8",
    )
    artifacts.append(str(summary))

    return {
        "ok": True,
        "artifact": str(summary),
        "artifacts": artifacts,
        "community": valid_comm,
        "notes": notes,
    }
