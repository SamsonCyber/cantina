"""Cantina plugin: nfs_enum — showmount + nmap nfs scripts (enum only)."""
from __future__ import annotations
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import match_service, tool_exists, run_cmd, finding, write_summary, nmap_scripts  # noqa: E402

PLUGIN = {
    "name": "nfs_enum",
    "services": ["nfs"],
    "ports": [2049],
    "enabled": True,
    "replaces_builtin": True,
    "description": "NFS showmount / nmap enum",
    "priority": 50,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}

def match(signals):
    return match_service(signals, {"nfs"}, {2049})

def run(ctx):
    target = ctx.target
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts, notes = [], []
    ofile = pdir / "nmap_nfs.txt"
    content = nmap_scripts(ctx, "111,2049", "nfs-ls,nfs-showmount,nfs-statfs", ofile)
    # nmap_scripts expects int port - fix: pass 2049 only and dual ports in extra
    if not content and tool_exists("nmap"):
        ping = (ctx.extra or {}).get("ping_flag") or ""
        run_cmd(ctx, f"nmap {ping} -p 111,2049 --script 'nfs-ls,nfs-showmount,nfs-statfs' -oN {ofile} {target} 2>/dev/null", 60)
        if ofile.exists():
            content = ofile.read_text(errors="replace")
    if content:
        arts.append(str(ofile))
        notes.append("nmap_nfs")
    if tool_exists("showmount"):
        out, _, _ = run_cmd(ctx, f"showmount -e {target} 2>/dev/null", 15)
        if out and "Export list" in out:
            ofile = pdir / "nfs_exports.txt"
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            for m in re.finditer(r"^(/\\S+)\\s+(.+)$", out, re.MULTILINE):
                path, access = m.group(1), m.group(2).strip()
                if access in ("*", "(everyone)"):
                    finding(ctx, "CRITICAL", "NFS", f"World-accessible NFS export: {path}",
                            f"mount -t nfs {target}:{path} /mnt/nfs")
                else:
                    finding(ctx, "WARNING", "NFS", f"NFS export: {path} ({access})")
            notes.append("exports_found")
    notes.append("enum_only")
    return write_summary(ctx, "nfs_enum", notes, arts)
