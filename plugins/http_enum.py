"""
Cantina plugin: http_enum (replaces built-in HTTP recon core path).

Probe → decide → light fingerprint / dirbust hints (enum only).
Full heavy tools run when present via ctx.run_cmd; no auto-exploit.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _plugin_util import (  # noqa: E402
    match_service, tool_exists, run_cmd, finding, write_summary,
)

PLUGIN = {
    "name": "http_enum",
    "services": ["http", "https"],
    "ports": [80, 443, 3000, 8000, 8080, 8443, 8888],
    "enabled": True,
    "replaces_builtin": True,
    "description": "HTTP probe + enum tools (dirbust/whatweb when present)",
    "priority": 40,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}


def match(signals):
    return match_service(
        signals,
        {"http", "https", "http-proxy", "ssl/http", "www"},
        {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090},
    )


def run(ctx):
    port = int(ctx.port)
    scheme = "https" if port in (443, 8443, 9443) or "ssl" in (ctx.service or "") or "https" in (ctx.service or "") else "http"
    url = f"{scheme}://{ctx.target}:{port}"
    pdir = Path(ctx.port_dir)
    pdir.mkdir(parents=True, exist_ok=True)
    arts = []
    notes = [f"url={url}"]

    try:
        from cantina import parse_http_probe, decide_http_actions, actions_to_run
    except ImportError:
        parse_http_probe = None
        decide_http_actions = None
        actions_to_run = None

    hdr, _, _ = run_cmd(ctx, f"curl -skI --max-time 5 -A 'cantina-plugin' {url} 2>/dev/null", 10)
    body, _, _ = run_cmd(ctx, f"curl -sk --max-time 5 -A 'cantina-plugin' {url} 2>/dev/null | head -c 2048", 10)
    probe = pdir / "http_probe.txt"
    probe.write_text(f"URL: {url}\n--- headers ---\n{hdr}\n--- body ---\n{body}\n", encoding="utf-8")
    arts.append(str(probe))

    signals = {}
    if parse_http_probe:
        signals = parse_http_probe(hdr, body)
        notes.append(f"looks_http={signals.get('looks_http')}")
        notes.append(f"real_app={signals.get('real_app')}")
        notes.append(f"cms={signals.get('cms')}")
    else:
        signals = {"looks_http": bool(hdr), "real_app": bool(body), "cms": None, "status": None}

    present = set()
    for t in ("whatweb", "feroxbuster", "ffuf", "gobuster", "nikto", "wpscan", "sslscan", "jarjar", "dirbust"):
        if t == "dirbust":
            if any(tool_exists(x) for x in ("feroxbuster", "ffuf", "gobuster")):
                present.add("dirbust")
        elif t == "jarjar":
            continue
        elif tool_exists(t):
            present.add(t)
    present.add("http_probe")

    want = set()
    if decide_http_actions and actions_to_run:
        actions = decide_http_actions(
            signals, depth=ctx.depth or "normal", port=port, tools_present=present,
        )
        if callable(ctx.log_decision):
            try:
                ctx.log_decision("http", port, actions, extra={"url": url, "plugin": "http_enum"})
            except Exception:
                pass
        want = {a["tool"] for a in actions_to_run(actions)}
    else:
        if signals.get("looks_http"):
            want = {"whatweb", "dirbust"} if signals.get("real_app") else {"whatweb"}

    if "whatweb" in want and tool_exists("whatweb"):
        ofile = pdir / "whatweb.txt"
        out, _, _ = run_cmd(ctx, f"whatweb {url} --color=never 2>/dev/null", 30)
        if out:
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))
            notes.append("whatweb_ok")

    if "dirbust" in want:
        wl = "/usr/share/wordlists/dirb/common.txt"
        if tool_exists("feroxbuster"):
            ofile = pdir / "feroxbuster.txt"
            run_cmd(ctx, f"feroxbuster -u {url} -w {wl} -t 20 -o {ofile} --no-state -q 2>/dev/null", 120)
            notes.append("dirbust=feroxbuster")
        elif tool_exists("ffuf"):
            ofile = pdir / "ffuf.csv"
            run_cmd(ctx, f"ffuf -u {url}/FUZZ -w {wl} -mc all -fc 404 -o {ofile} -of csv 2>/dev/null", 120)
            notes.append("dirbust=ffuf")
        elif tool_exists("gobuster"):
            ofile = pdir / "gobuster.txt"
            run_cmd(ctx, f"gobuster dir -u {url} -w {wl} -t 20 -o {ofile} 2>/dev/null", 120)
            notes.append("dirbust=gobuster")
        else:
            notes.append("dirbust_tools_missing")

    if "wpscan" in want and tool_exists("wpscan"):
        ofile = pdir / "wpscan.txt"
        run_cmd(ctx, f"wpscan --url {url} -e vp,vt,u --no-banner -o {ofile} 2>/dev/null", 180)
        notes.append("wpscan")
        finding(ctx, "WARNING", "Web", f"WordPress signals on port {port}")

    if scheme == "https" and tool_exists("sslscan"):
        ofile = pdir / "sslscan.txt"
        out, _, _ = run_cmd(ctx, f"sslscan --no-colour {ctx.target}:{port} 2>/dev/null", 30)
        if out:
            ofile.write_text(out, encoding="utf-8")
            arts.append(str(ofile))

    if not signals.get("looks_http"):
        notes.append("not_http_or_empty")

    finding(ctx, "INFO", "Web", f"HTTP enum plugin on {url}")
    return write_summary(ctx, "http_enum", notes, arts)
