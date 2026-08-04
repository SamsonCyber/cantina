#!/usr/bin/env python3
"""
Cantina plugin model — discover, select, run enum-only recon plugins.

Operators add recon behavior by dropping a Python module into a plugins
directory (or registering in-memory for tests). Plugins declare metadata
(name, service/port triggers, enabled) and implement match + run.

Legal: Enumeration only. No exploitation. No credential-spray auto-run.
OSCP exam safe defaults. Plugin authors who violate that are on their own.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

# ── Contract ────────────────────────────────────────────────────────────

LEGAL_ENUM_ONLY = "enumeration-only; OSCP-safe; no exploit/spray auto-run"

# Banned auto tools in plugin-driven command templates (defense in depth)
_BANNED_PLUGIN_TOOLS = frozenset({
    "hydra", "medusa", "patator", "crowbar", "ncrack",
    "redis-brute", "vnc-brute", "snmp-brute", "msfconsole",
})


@dataclass
class PluginMeta:
    """Metadata every registered plugin exposes."""
    name: str
    services: list[str] = field(default_factory=list)  # e.g. ["http","smb"] or ["*"]
    ports: list[int] = field(default_factory=list)     # optional explicit ports
    enabled: bool = True
    description: str = ""
    priority: int = 100  # lower runs first
    legal: str = LEGAL_ENUM_ONLY
    path: str = ""  # source path if loaded from disk
    # When True, built-in recon for meta.services is skipped (plugin owns the path)
    replaces_builtin: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "services": list(self.services),
            "ports": list(self.ports),
            "enabled": bool(self.enabled),
            "description": self.description,
            "priority": int(self.priority),
            "legal": self.legal,
            "path": self.path,
            "replaces_builtin": bool(self.replaces_builtin),
        }


@dataclass
class PluginSignals:
    """What a plugin can match against (pure; no I/O)."""
    port: int
    proto: str = "tcp"
    service: str = ""
    version: str = ""
    svc_type: str = ""  # select_service_type result or empty

    def to_dict(self) -> dict:
        return {
            "port": int(self.port),
            "proto": self.proto or "tcp",
            "service": (self.service or "").lower(),
            "version": (self.version or "").lower(),
            "svc_type": (self.svc_type or "").lower(),
        }


@dataclass
class PluginContext:
    """Runtime context passed to plugin.run (has I/O helpers when wired)."""
    target: str
    port: int
    proto: str
    service: str
    version: str
    svc_type: str
    outdir: Path
    recon_dir: Path
    port_dir: Path
    depth: str = "normal"
    run_cmd: Optional[Callable[..., Any]] = None  # optional cantina.run wrapper
    add_finding: Optional[Callable[..., Any]] = None  # scanner.add_finding
    log_decision: Optional[Callable[..., Any]] = None  # scanner._log_decision
    extra: dict = field(default_factory=dict)


@dataclass
class RegisteredPlugin:
    """One discovered/registered plugin."""
    meta: PluginMeta
    match_fn: Callable[[dict], bool]
    run_fn: Callable[[PluginContext], Any]
    source: str = "disk"  # disk | memory | toml

    @property
    def name(self) -> str:
        return self.meta.name


@dataclass
class PluginRegistry:
    """Ordered registry of plugins."""
    plugins: list[RegisteredPlugin] = field(default_factory=list)

    def register(self, plugin: RegisteredPlugin) -> None:
        # Replace same name if re-registering
        self.plugins = [p for p in self.plugins if p.name != plugin.name]
        self.plugins.append(plugin)
        self.plugins.sort(key=lambda p: (p.meta.priority, p.name))

    def list_plugins(self, include_disabled: bool = True) -> list[dict]:
        out = []
        for p in self.plugins:
            if not include_disabled and not p.meta.enabled:
                continue
            d = p.meta.to_dict()
            d["source"] = p.source
            out.append(d)
        return out

    def get(self, name: str) -> Optional[RegisteredPlugin]:
        for p in self.plugins:
            if p.name == name:
                return p
        return None

    def __len__(self) -> int:
        return len(self.plugins)


# ── Pure match / select ─────────────────────────────────────────────────

def default_match(meta: PluginMeta, signals: dict) -> bool:
    """Default matcher: services and/or ports from metadata.

    signals keys: port, proto, service, version, svc_type (all lowercased strings where applicable)
    """
    if not meta.enabled:
        return False
    port = int(signals.get("port") or 0)
    svc = (signals.get("service") or "").lower()
    svc_type = (signals.get("svc_type") or "").lower()
    services = [s.lower() for s in (meta.services or [])]
    ports = [int(p) for p in (meta.ports or [])]

    if not services and not ports:
        # No triggers declared → never auto-select (must use custom match_fn)
        return False

    port_ok = (not ports) or (port in ports)
    if services:
        if "*" in services:
            svc_ok = True
        else:
            svc_ok = (
                svc in services
                or svc_type in services
                or any(s in svc for s in services if s)
            )
    else:
        svc_ok = True

    return bool(port_ok and svc_ok)


def replaced_builtin_services(registry: Optional[PluginRegistry]) -> set[str]:
    """Service keys owned by enabled plugins with replaces_builtin=True."""
    out: set[str] = set()
    if registry is None:
        return out
    for p in registry.plugins:
        if not p.meta.enabled or not p.meta.replaces_builtin:
            continue
        for s in p.meta.services or []:
            s = (s or "").lower().strip()
            if s and s != "*":
                out.add(s)
    return out


def select_plugins(
    registry: PluginRegistry,
    signals: dict | PluginSignals,
    *,
    include_disabled: bool = False,
) -> list[RegisteredPlugin]:
    """Return enabled plugins that match signals (pure selection)."""
    if isinstance(signals, PluginSignals):
        sig = signals.to_dict()
    else:
        sig = {
            "port": int(signals.get("port") or 0),
            "proto": (signals.get("proto") or "tcp"),
            "service": (signals.get("service") or "").lower(),
            "version": (signals.get("version") or "").lower(),
            "svc_type": (signals.get("svc_type") or "").lower(),
        }
    selected = []
    for p in registry.plugins:
        if not include_disabled and not p.meta.enabled:
            continue
        try:
            if p.match_fn(sig):
                selected.append(p)
        except Exception:
            # Bad matcher → skip, never abort recon
            continue
    return selected


def plan_plugin_jobs(port_map: dict, registry: PluginRegistry, select_service_type_fn) -> list[dict]:
    """Build independent plugin×port jobs (pure; no I/O).

    port_map: {port: {port, proto, service, version}} from Scanner.tcp/udp_ports.
    Returns list of dicts with keys:
      plugin, plugin_name, port, proto, service, version, svc_type
    Dedupes (plugin_name, port, proto). Order is stable by port then plugin priority.
    """
    jobs = []
    seen = set()
    if not registry or not port_map:
        return jobs
    for port, rec in sorted(port_map.items(), key=lambda x: int(x[0])):
        rec = rec or {}
        proto = (rec.get("proto") or "tcp").lower()
        svc = (rec.get("service") or "").lower()
        ver = (rec.get("version") or "").lower()
        try:
            svc_type = select_service_type_fn(int(port), svc, ver, proto) or ""
        except Exception:
            svc_type = ""
        signals = {
            "port": int(port),
            "proto": proto,
            "service": svc,
            "version": ver,
            "svc_type": (svc_type or "").lower(),
        }
        for plug in select_plugins(registry, signals):
            key = (plug.name, int(port), proto)
            if key in seen:
                continue
            seen.add(key)
            jobs.append({
                "plugin": plug,
                "plugin_name": plug.name,
                "port": int(port),
                "proto": proto,
                "service": svc,
                "version": ver,
                "svc_type": svc_type,
            })
    return jobs


def actions_heavy_skipped(actions) -> list[str]:
    """Names of heavy tools decided not to run (effectiveness signal)."""
    out = []
    for a in actions or []:
        if a.get("weight") == "heavy" and not a.get("run"):
            out.append(a.get("tool") or "?")
    return out


def actions_light_run(actions) -> list[str]:
    """Names of light tools decided to run."""
    out = []
    for a in actions or []:
        if a.get("run") and (a.get("weight") or "light") == "light":
            out.append(a.get("tool") or "?")
    return out


def format_plugin_list(registry: PluginRegistry, *, include_disabled: bool = True) -> str:
    """Human-readable plugin list for CLI (no network)."""
    rows = registry.list_plugins(include_disabled=include_disabled)
    if not rows:
        return (
            "Cantina plugins: (none loaded)\n"
            "  Drop enum-only Python modules into --plugins-dir "
            "(default: <tools>/plugins or ./cantina_plugins).\n"
            "  Each module sets PLUGIN = {name, services, ports, enabled, ...} "
            "and optional match()/run().\n"
            f"  Legal: {LEGAL_ENUM_ONLY}\n"
        )
    lines = [f"Cantina plugins: {len(rows)} loaded", f"Legal default: {LEGAL_ENUM_ONLY}", ""]
    for d in rows:
        state = "ON " if d.get("enabled") else "OFF"
        svcs = ",".join(d.get("services") or []) or "-"
        ports = ",".join(str(p) for p in (d.get("ports") or [])) or "-"
        desc = d.get("description") or ""
        src = d.get("path") or d.get("source") or ""
        lines.append(
            f"  [{state}] {d['name']:<20} services={svcs:<16} ports={ports:<12} "
            f"pri={d.get('priority', 100)}  {desc}"
        )
        if src:
            lines.append(f"         source: {src}")
    lines.append("")
    return "\n".join(lines)


# ── Discovery ───────────────────────────────────────────────────────────

def default_plugin_dirs(extra: Optional[str] = None) -> list[Path]:
    """Search paths for plugin modules (first existing wins for duplicates by name)."""
    dirs = []
    if extra:
        dirs.append(Path(extra).expanduser())
    # Next to this module: tools/plugins
    here = Path(__file__).resolve().parent
    dirs.append(here / "plugins")
    dirs.append(Path("./cantina_plugins").resolve())
    dirs.append(Path(os.path.expanduser("~/.config/cantina/plugins")))
    dirs.append(Path(os.path.expanduser("~/tools/cantina_plugins")))
    # de-dupe preserve order
    seen = set()
    out = []
    for d in dirs:
        key = str(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _safe_plugin_name(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$", name or ""))


def register_plugin_from_dict(
    registry: PluginRegistry,
    meta_dict: dict,
    *,
    match_fn: Optional[Callable] = None,
    run_fn: Optional[Callable] = None,
    source: str = "memory",
    path: str = "",
) -> RegisteredPlugin:
    """Register a plugin from a meta dict + optional callables (tests / toml)."""
    name = (meta_dict.get("name") or "").strip()
    if not name or not _safe_plugin_name(name):
        raise ValueError(f"invalid plugin name: {name!r}")
    meta = PluginMeta(
        name=name,
        services=list(meta_dict.get("services") or []),
        ports=[int(p) for p in (meta_dict.get("ports") or [])],
        enabled=bool(meta_dict.get("enabled", True)),
        description=str(meta_dict.get("description") or ""),
        priority=int(meta_dict.get("priority", 100)),
        legal=str(meta_dict.get("legal") or LEGAL_ENUM_ONLY),
        path=path or str(meta_dict.get("path") or ""),
        replaces_builtin=bool(meta_dict.get("replaces_builtin", False)),
    )
    if match_fn is None:
        def match_fn(signals, _meta=meta):  # noqa: B023
            return default_match(_meta, signals)
    if run_fn is None:
        def run_fn(ctx):  # noqa: B023
            return {"ok": True, "skipped": True, "reason": "no run() defined"}
    plugin = RegisteredPlugin(meta=meta, match_fn=match_fn, run_fn=run_fn, source=source)
    registry.register(plugin)
    return plugin


def load_plugin_module(path: Path, registry: PluginRegistry) -> Optional[RegisteredPlugin]:
    """Load one .py plugin file into the registry. Returns RegisteredPlugin or None."""
    path = Path(path)
    if not path.is_file() or path.suffix != ".py":
        return None
    if path.name.startswith("_"):
        return None
    mod_name = f"cantina_plugin_{path.stem}"
    try:
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        # Isolate: do not put on sys.modules permanently if load fails mid-way
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(mod_name, None)
        return None

    raw = getattr(mod, "PLUGIN", None) or getattr(mod, "META", None)
    if not isinstance(raw, dict):
        sys.modules.pop(mod_name, None)
        return None

    match_fn = getattr(mod, "match", None)
    run_fn = getattr(mod, "run", None)
    try:
        plugin = register_plugin_from_dict(
            registry,
            raw,
            match_fn=match_fn if callable(match_fn) else None,
            run_fn=run_fn if callable(run_fn) else None,
            source="disk",
            path=str(path.resolve()),
        )
        return plugin
    except ValueError:
        sys.modules.pop(mod_name, None)
        return None


def discover_plugins(
    plugins_dir: Optional[str] = None,
    *,
    registry: Optional[PluginRegistry] = None,
    extra_dirs: Optional[list] = None,
) -> PluginRegistry:
    """Discover plugins from directories. Pure-ish: filesystem only, no recon I/O."""
    reg = registry or PluginRegistry()
    dirs = []
    if plugins_dir:
        dirs.append(Path(plugins_dir).expanduser())
    if extra_dirs:
        dirs.extend(Path(d).expanduser() for d in extra_dirs)
    if not dirs:
        dirs = default_plugin_dirs()
    else:
        # still append defaults after explicit so explicit wins on name collide (register replaces)
        # Actually: load explicit first, then defaults only if name free
        dirs = dirs + [d for d in default_plugin_dirs() if d not in dirs]

    seen_files = set()
    for d in dirs:
        try:
            if not d.is_dir():
                continue
        except OSError:
            continue
        for py in sorted(d.glob("*.py")):
            key = str(py.resolve()) if py.exists() else str(py)
            if key in seen_files:
                continue
            seen_files.add(key)
            load_plugin_module(py, reg)
    return reg


def toml_commands_as_plugins(
    plugin_config: dict,
    registry: Optional[PluginRegistry] = None,
) -> PluginRegistry:
    """Fold legacy cantina.toml [service] commands = [...] into the registry.

    Each service section becomes one plugin that runs the command templates
    via ctx.run_cmd when present. Enum only — banned tool names are skipped.
    """
    reg = registry or PluginRegistry()
    if not plugin_config:
        return reg
    for section, body in plugin_config.items():
        if section in ("global", "plugins") or not isinstance(body, dict):
            continue
        commands = body.get("commands") or []
        if not commands:
            continue
        svc = section.lower()
        name = f"toml_{svc}"

        def _make_run(cmds, svc_name):
            def run(ctx: PluginContext):
                results = []
                for tmpl in cmds:
                    try:
                        cmd = tmpl.format(
                            target=ctx.target,
                            port=ctx.port,
                            url=ctx.extra.get("url") or f"http://{ctx.target}:{ctx.port}",
                            outdir=ctx.recon_dir,
                            port_dir=ctx.port_dir,
                        )
                    except Exception as e:
                        results.append({"cmd": tmpl, "error": str(e)})
                        continue
                    # Block banned spray tools in template
                    head = (cmd.split() or [""])[0].lower()
                    base = Path(head).name.lower()
                    if base in _BANNED_PLUGIN_TOOLS or any(
                        b in cmd.lower() for b in _BANNED_PLUGIN_TOOLS
                    ):
                        results.append({
                            "cmd": cmd,
                            "skipped": True,
                            "reason": "banned auto-spray/exploit tool in template",
                        })
                        continue
                    if ctx.run_cmd is None:
                        results.append({"cmd": cmd, "skipped": True, "reason": "no run_cmd"})
                        continue
                    try:
                        out = ctx.run_cmd(cmd)
                        results.append({"cmd": cmd, "result": out})
                    except Exception as e:
                        results.append({"cmd": cmd, "error": str(e)})
                # Write summary artifact
                try:
                    art = ctx.port_dir / f"plugin_toml_{svc_name}.txt"
                    lines = []
                    for r in results:
                        lines.append(str(r))
                    art.write_text("\n".join(lines) + "\n", encoding="utf-8")
                except Exception:
                    art = None
                return {"ok": True, "results": results, "artifact": str(art) if art else None}

            return run

        register_plugin_from_dict(
            reg,
            {
                "name": name,
                "services": [svc],
                "ports": [],
                "enabled": True,
                "description": f"Legacy cantina.toml commands for {svc}",
                "priority": 200,
            },
            run_fn=_make_run(list(commands), svc),
            source="toml",
            path="cantina.toml",
        )
    return reg


# ── Execution ───────────────────────────────────────────────────────────

def run_plugin(plugin: RegisteredPlugin, ctx: PluginContext) -> dict:
    """Execute one plugin; never raises to caller. Returns result dict."""
    if not plugin.meta.enabled:
        return {
            "plugin": plugin.name,
            "ok": False,
            "skipped": True,
            "reason": "disabled",
        }
    try:
        result = plugin.run_fn(ctx)
        if result is None:
            result = {"ok": True}
        if not isinstance(result, dict):
            result = {"ok": True, "result": result}
        result.setdefault("plugin", plugin.name)
        result.setdefault("ok", True)
        return result
    except Exception as e:
        return {
            "plugin": plugin.name,
            "ok": False,
            "error": f"{type(e).__name__}: {e}",
            "traceback": traceback.format_exc(limit=6),
        }


def run_plugins_for_signals(
    registry: PluginRegistry,
    signals: dict | PluginSignals,
    ctx: PluginContext,
) -> list[dict]:
    """Select + run all matching enabled plugins for one port/service."""
    selected = select_plugins(registry, signals)
    results = []
    for p in selected:
        results.append(run_plugin(p, ctx))
    return results


def build_context_from_scanner(
    scanner,
    port: int,
    *,
    proto: str = "tcp",
    service: str = "",
    version: str = "",
    svc_type: str = "",
    run_cmd=None,
    extra: Optional[dict] = None,
) -> PluginContext:
    """Build PluginContext from a Cantina Scanner-like object."""
    recon_dir = Path(getattr(scanner, "recon_dir", Path(".")))
    outdir = Path(getattr(scanner, "outdir", recon_dir.parent))
    # Prefer scanner.port_dir / port_recon_subdir if available
    port_dir = recon_dir / f"{proto}{int(port)}"
    try:
        if hasattr(scanner, "port_dir"):
            port_dir = Path(scanner.port_dir(port, proto))
        else:
            port_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        port_dir.mkdir(parents=True, exist_ok=True)
    add_finding = getattr(scanner, "add_finding", None)
    log_decision = getattr(scanner, "_log_decision", None)
    return PluginContext(
        target=str(getattr(scanner, "target", "")),
        port=int(port),
        proto=proto or "tcp",
        service=service or "",
        version=version or "",
        svc_type=svc_type or "",
        outdir=outdir,
        recon_dir=recon_dir,
        port_dir=Path(port_dir),
        depth=str(getattr(scanner, "recon_depth", "normal") or "normal"),
        run_cmd=run_cmd,
        add_finding=add_finding if callable(add_finding) else None,
        log_decision=log_decision if callable(log_decision) else None,
        extra=dict(extra or {}),
    )
