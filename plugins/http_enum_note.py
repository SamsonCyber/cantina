"""
Example Cantina plugin: write a short enum note for HTTP ports.

Enumeration only. No exploitation. No credential spray.
"""

PLUGIN = {
    "name": "http_enum_note",
    "services": ["http", "https"],
    "ports": [],
    "enabled": True,
    "description": "Write enum note under recon/tcpN for HTTP services",
    "priority": 150,
    "legal": "enumeration-only; OSCP-safe; no exploit/spray auto-run",
}


def match(signals):
    """Match HTTP-ish services or classic web ports."""
    svc = (signals.get("service") or "").lower()
    svc_type = (signals.get("svc_type") or "").lower()
    port = int(signals.get("port") or 0)
    if svc_type in ("http", "https"):
        return True
    if "http" in svc or "https" in svc:
        return True
    return port in (80, 443, 8080, 8443, 8000, 8888)


def run(ctx):
    """Write a small note file; enum only."""
    art = ctx.port_dir / "plugin_http_enum_note.txt"
    scheme = "https" if ctx.port in (443, 8443) or "ssl" in ctx.service else "http"
    body = (
        f"# Cantina plugin http_enum_note (enumeration only)\n"
        f"target={ctx.target}\n"
        f"port={ctx.port}/{ctx.proto}\n"
        f"service={ctx.service}\n"
        f"version={ctx.version}\n"
        f"svc_type={ctx.svc_type}\n"
        f"suggested=curl -skI {scheme}://{ctx.target}:{ctx.port}/\n"
        f"suggested=whatweb {scheme}://{ctx.target}:{ctx.port}/\n"
    )
    art.write_text(body, encoding="utf-8")
    return {"ok": True, "artifact": str(art)}
