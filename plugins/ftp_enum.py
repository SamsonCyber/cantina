"""
Cantina plugin: FTP enum (replaces built-in ftp recon path).

Phases (enumeration only, no auto-exploit):
  1. nmap ftp-anon / bounce / syst / known-backdoor detection scripts
  2. Banner grab if version missing
  3. Known-version notes (searchsploit hints only)
  4. Anon list + interesting files when anon allowed
  5. Anon write probe when anon allowed (lab enum signal)

Legal: enumeration-only; OSCP-safe; no exploit/spray auto-run.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

PLUGIN = {
    "name": "ftp_enum",
    "services": ["ftp"],
    "ports": [21],
    "enabled": True,
    "replaces_builtin": True,
    "description": "FTP anon/banner/version enum (no auto-exploit)",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

_VULN_VERSIONS = {
    "vsftpd 2.3.4": "vsftpd 2.3.4 backdoor (CVE-2011-2523). Note only — no auto-exploit.",
    "ProFTPD 1.3.3": "ProFTPD 1.3.3c mod_copy (CVE-2015-3306). Enum note only.",
    "ProFTPD 1.3.5": "ProFTPD 1.3.5 mod_copy. Enum note only.",
    "FileZilla Server 0.9": "FileZilla Server 0.9.x local privilege escalation.",
    "Pure-FTPd": "Check for CVE-2020-9365 if version < 1.0.50.",
}

_INTERESTING_EXT = (
    ".conf", ".cfg", ".txt", ".bak", ".old", ".sql", ".db",
    ".xml", ".ini", ".log", ".key", ".pem", ".zip", ".tar",
    ".gz", ".7z", ".kdbx", "pass", "cred", "secret", "backup",
    ".ssh", "shadow", "htpasswd",
)


def match(signals):
    svc = (signals.get("service") or "").lower()
    svc_type = (signals.get("svc_type") or "").lower()
    port = int(signals.get("port") or 0)
    if svc_type == "ftp" or svc == "ftp":
        return True
    return port == 21


def _tool_exists(name: str) -> bool:
    return bool(shutil.which(name))


def _run(ctx, cmd: str, timeout: int = 60):
    if ctx.run_cmd is None:
        return "", "no run_cmd", 1
    try:
        out = ctx.run_cmd(cmd, timeout=timeout)
        if isinstance(out, tuple) and len(out) == 3:
            return out[0] or "", out[1] or "", int(out[2] if out[2] is not None else 1)
        if isinstance(out, tuple) and len(out) == 2:
            return out[0] or "", "", int(out[1] if out[1] is not None else 1)
        return str(out or ""), "", 0
    except TypeError:
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
    try:
        from cantina import decide_ftp_actions, actions_to_run
    except ImportError:
        decide_ftp_actions = None
        actions_to_run = None

    target = ctx.target
    port = int(ctx.port)
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    recon_dir = Path(ctx.recon_dir)
    ping_flag = (ctx.extra or {}).get("ping_flag") or ""
    artifacts = []
    notes = []

    # Phase 1: nmap FTP scripts
    ofile = pdir / "nmap_ftp.txt"
    anon_allowed = False
    ftp_version = ""
    if _tool_exists("nmap"):
        cmd = (
            f"nmap {ping_flag} -p {port} --script "
            f"'ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor,ftp-proftpd-backdoor' "
            f"-oN {ofile} {target} 2>/dev/null"
        )
        _run(ctx, cmd, timeout=60)
        if ofile.exists():
            content = ofile.read_text(errors="replace")
            artifacts.append(str(ofile))
            if "Anonymous FTP login allowed" in content:
                anon_allowed = True
                notes.append("anon_allowed")
                _finding(ctx, "CRITICAL", "FTP", "Anonymous FTP login allowed", f"ftp {target}")
            if "VULNERABLE" in content:
                notes.append("nmap_vulnerable")
                _finding(ctx, "CRITICAL", "FTP", "FTP vulnerability detected")
            m = re.search(r"ftp-syst:.*?(\S+FTP\S*\s+\S+)", content, re.DOTALL)
            if m:
                ftp_version = m.group(1)
    else:
        notes.append("nmap_missing")

    if decide_ftp_actions and actions_to_run:
        actions = decide_ftp_actions(
            anon_allowed=anon_allowed, has_version=bool(ftp_version),
        )
        want = {a["tool"] for a in actions_to_run(actions)}
        if callable(ctx.log_decision):
            try:
                ctx.log_decision(
                    "ftp", port, actions,
                    extra={
                        "anon_allowed": anon_allowed,
                        "version": ftp_version,
                        "plugin": "ftp_enum",
                    },
                )
            except Exception:
                pass
    else:
        want = {"nmap_ftp_scripts"}
        if not ftp_version:
            want.add("banner_grab")
        if anon_allowed:
            want.update({"anon_list", "anon_write_test"})

    # Phase 2: banner grab
    if "banner_grab" in want and not ftp_version:
        stdout, _, _ = _run(
            ctx,
            f"timeout 3 bash -c 'echo | nc -nvw 2 {target} {port} 2>&1' | head -3",
            timeout=8,
        )
        if stdout:
            m = re.search(r"220[- ](.+)", stdout)
            if m:
                ftp_version = m.group(1).strip()
                notes.append(f"banner={ftp_version}")

    # Version notes (no auto-exploit)
    if ftp_version:
        for vstr, desc in _VULN_VERSIONS.items():
            if vstr.lower() in ftp_version.lower():
                notes.append(f"known_vuln={vstr}")
                _finding(ctx, "CRITICAL", "FTP", desc, f"searchsploit {vstr}")

    # Phase 3: anon list
    if "anon_list" in want:
        stdout, _, rc = _run(
            ctx,
            f"curl -s --list-only ftp://{target}:{port}/ 2>/dev/null",
            timeout=15,
        )
        if stdout:
            files = stdout.strip().splitlines()
            ofile_ls = pdir / "ftp_anonymous_listing.txt"
            ofile_ls.write_text(stdout, encoding="utf-8")
            artifacts.append(str(ofile_ls))
            # also keep legacy path under recon/ for familiarity
            try:
                (recon_dir / "ftp_anonymous_listing.txt").write_text(stdout, encoding="utf-8")
            except Exception:
                pass
            notes.append(f"anon_files={len(files)}")
            interesting = [
                f for f in files
                if any(ext in f.lower() for ext in _INTERESTING_EXT)
            ]
            if interesting:
                _finding(
                    ctx, "WARNING", "FTP",
                    f"Interesting files on anon FTP: {', '.join(interesting[:10])}",
                    f"wget -r ftp://anonymous:@{target}:{port}/",
                )

        if "anon_write_test" in want:
            _, _, rc_wr = _run(
                ctx,
                f"curl -s -T /dev/null ftp://{target}:{port}/._write_test_ "
                f"--user anonymous: 2>/dev/null",
                timeout=10,
            )
            _run(
                ctx,
                f"curl -s ftp://{target}:{port}/ -Q 'DELE ._write_test_' "
                f"--user anonymous: 2>/dev/null",
                timeout=5,
            )
            if rc_wr == 0:
                notes.append("anon_writable")
                _finding(
                    ctx, "CRITICAL", "FTP", "Anonymous FTP write access",
                    f"curl -T shell.php ftp://anonymous:@{target}:{port}/",
                )
    else:
        notes.append("anon_list_skipped")

    summary = pdir / "plugin_ftp_enum.txt"
    summary.write_text(
        "# ftp_enum plugin (enumeration only)\n"
        f"target={target}\nport={port}\n"
        f"anon_allowed={anon_allowed}\n"
        f"version={ftp_version}\n"
        f"notes={'; '.join(notes)}\n"
        f"artifacts={len(artifacts)}\n",
        encoding="utf-8",
    )
    artifacts.append(str(summary))
    return {
        "ok": True,
        "artifact": str(summary),
        "artifacts": artifacts,
        "anon_allowed": anon_allowed,
        "version": ftp_version,
        "notes": notes,
    }
