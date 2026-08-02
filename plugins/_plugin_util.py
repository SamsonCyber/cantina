"""Shared helpers for Cantina enum plugins (not loaded as a PLUGIN)."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Optional

# Process-wide cache (same idea as cantina.tool_exists)
_TOOL_CACHE: dict = {}


def clear_tool_cache():
    _TOOL_CACHE.clear()


def tool_exists(name: str) -> bool:
    """PATH lookup with process-wide cache (speed: avoid repeated which)."""
    if not name:
        return False
    key = str(name)
    if key in _TOOL_CACHE:
        return _TOOL_CACHE[key]
    # Prefer cantina's cache when available so both stay in sync
    try:
        from cantina import tool_exists as _c_exists
        found = bool(_c_exists(key))
    except Exception:
        found = shutil.which(key) is not None
    _TOOL_CACHE[key] = found
    return found


def run_cmd(ctx, cmd: str, timeout: int = 60):
    """Return (stdout, stderr, rc) via ctx.run_cmd when wired."""
    if ctx.run_cmd is None:
        return "", "no run_cmd", 1
    try:
        out = ctx.run_cmd(cmd, timeout=timeout)
    except TypeError:
        try:
            out = ctx.run_cmd(cmd)
        except Exception as e:
            return "", str(e), 1
    except Exception as e:
        return "", str(e), 1
    if isinstance(out, tuple) and len(out) == 3:
        return out[0] or "", out[1] or "", int(out[2] if out[2] is not None else 1)
    if isinstance(out, tuple) and len(out) == 2:
        return out[0] or "", "", int(out[1] if out[1] is not None else 1)
    return str(out or ""), "", 0


def finding(ctx, severity: str, category: str, message: str, exploit_cmd: str = ""):
    if callable(getattr(ctx, "add_finding", None)):
        try:
            ctx.add_finding(severity, category, message, exploit_cmd=exploit_cmd)
        except TypeError:
            ctx.add_finding(severity, category, message)


def write_summary(ctx, name: str, lines: list[str], extra_artifacts: Optional[list] = None) -> dict:
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    summary = pdir / f"plugin_{name}.txt"
    body = [f"# {name} plugin (enumeration only)", f"target={ctx.target}", f"port={ctx.port}/{ctx.proto}"]
    body.extend(lines)
    summary.write_text("\n".join(body) + "\n", encoding="utf-8")
    arts = list(extra_artifacts or [])
    arts.append(str(summary))
    return {"ok": True, "artifact": str(summary), "artifacts": arts}


def nmap_scripts(ctx, port, scripts: str, outfile: Path, extra_flags: str = "") -> str:
    """Run nmap scripts to outfile; return content or empty. port may be int or '111,2049'."""
    if not tool_exists("nmap"):
        return ""
    ping = (ctx.extra or {}).get("ping_flag") or ""
    # Depth-aware timeout: quick recon fails faster when target is dead
    default_t = int((ctx.extra or {}).get("default_timeout") or 90)
    timeout = min(90, max(20, default_t))
    cmd = (
        f"nmap {ping} {extra_flags} -p {port} --script '{scripts}' "
        f"-oN {outfile} {ctx.target} 2>/dev/null"
    )
    run_cmd(ctx, cmd, timeout=timeout)
    if outfile.exists():
        return outfile.read_text(errors="replace")
    return ""


def match_service(signals: dict, names: set, ports: set) -> bool:
    svc = (signals.get("service") or "").lower()
    svc_type = (signals.get("svc_type") or "").lower()
    port = int(signals.get("port") or 0)
    if svc_type in names or svc in names:
        return True
    if any(n in svc for n in names if n):
        return True
    return port in ports
