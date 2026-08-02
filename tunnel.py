"""
tunnel.py - Shared tunnel/proxy awareness for the OSCP tool suite.

Detects Hyperdrive (ligolo), Chisel, SSH dynamic forwards, and manual SOCKS
proxies. Any tool imports this to auto-detect tunnels and route traffic.

Usage in tools:

    # Auto-detect: checks Hyperdrive state, env vars, common SOCKS ports
    from tunnel import tunnel_ctx
    ctx = tunnel_ctx("10.10.10.5")

    # Wrap shell commands with proxychains
    cmd = ctx.wrap("nmap -sV 10.10.10.5")

    # Patch Python sockets to go through SOCKS (for impacket/ldap3 tools)
    ctx.patch_sockets()   # All socket.socket() calls now go through SOCKS

    # Or get proxy info to do it yourself
    proxy = ctx.get_proxy()  # ("socks5", "127.0.0.1", 1080) or None

    # Manual proxy override (ignores auto-detect)
    from tunnel import tunnel_ctx_manual
    ctx = tunnel_ctx_manual("socks5://127.0.0.1:1080", "10.10.10.5")

Supports: Hyperdrive/ligolo, Chisel SOCKS, SSH -D, any SOCKS4/5 proxy.
Falls back gracefully if nothing is detected.
"""

import ipaddress
import json
import os
import socket as _stdlib_socket
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Tuple

STATE_FILE = "/tmp/ligolo_smart_state.json"

# Process-level cache
_state_cache = None
_state_cache_time = 0
_CACHE_TTL = 5

# Common SOCKS proxy ports to probe when no explicit config exists
_COMMON_SOCKS_PORTS = [1080, 1081, 9050, 9051, 8080, 1337]

# ── Proxy detection ─────────────────────────────────────────────────────

def _detect_proxy_env() -> Optional[Tuple[str, str, int]]:
    """Check environment variables for SOCKS proxy config.

    Supports:
        TUNNEL_PROXY=socks5://127.0.0.1:1080
        ALL_PROXY=socks5://127.0.0.1:1080
        SOCKS_PROXY=127.0.0.1:1080
    """
    for var in ["TUNNEL_PROXY", "ALL_PROXY", "SOCKS_PROXY", "socks_proxy", "all_proxy"]:
        val = os.environ.get(var, "").strip()
        if not val:
            continue
        return _parse_proxy_url(val)
    return None


def _parse_proxy_url(url: str) -> Optional[Tuple[str, str, int]]:
    """Parse 'socks5://host:port' or 'host:port' into (type, host, port)."""
    url = url.strip()
    proxy_type = "socks5"
    if "://" in url:
        scheme, rest = url.split("://", 1)
        proxy_type = scheme.lower()
        url = rest
    if ":" in url:
        host, port_str = url.rsplit(":", 1)
        try:
            port = int(port_str)
            return (proxy_type, host, port)
        except ValueError:
            pass
    return None


def _probe_socks_port(host: str = "127.0.0.1", port: int = 1080, timeout: float = 0.3) -> bool:
    """Quick check if a port is listening (likely a SOCKS proxy)."""
    try:
        s = _stdlib_socket.socket(_stdlib_socket.AF_INET, _stdlib_socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except OSError:
        return False


def _detect_proxy_ports() -> Optional[Tuple[str, str, int]]:
    """Probe common local SOCKS ports to find an active proxy."""
    for port in _COMMON_SOCKS_PORTS:
        if _probe_socks_port("127.0.0.1", port):
            return ("socks5", "127.0.0.1", port)
    return None


def _detect_proxychains_active() -> bool:
    """Check if we're already running under proxychains."""
    ld = os.environ.get("LD_PRELOAD", "")
    return "proxychains" in ld.lower()


def detect_proxy() -> Optional[Tuple[str, str, int]]:
    """Auto-detect any active SOCKS proxy.

    Priority:
    1. TUNNEL_PROXY / ALL_PROXY / SOCKS_PROXY env var
    2. Hyperdrive state file (ligolo SOCKS)
    3. Probe common local SOCKS ports (chisel, SSH -D, etc.)
    """
    # 1. Env var (explicit override)
    env_proxy = _detect_proxy_env()
    if env_proxy:
        return env_proxy

    # 2. Hyperdrive state
    state = _load_state()
    if state.get("proxy_pid") and state.get("routes"):
        return ("socks5", "127.0.0.1", 1080)

    # 3. Port probe
    return _detect_proxy_ports()


# ── TunnelContext ────────────────────────────────────────────────────────

@dataclass
class TunnelContext:
    """Context object describing tunnel state for a given target."""
    tunneled: bool = False
    interface: str = ""
    subnet: str = ""
    all_routes: List[str] = None
    proxy_pid: Optional[int] = None
    session_count: int = 0
    proxy: Optional[Tuple[str, str, int]] = None  # (type, host, port)
    source: str = ""  # "hyperdrive", "env", "probe", "manual", ""

    def __post_init__(self):
        if self.all_routes is None:
            self.all_routes = []

    def wrap(self, cmd: str) -> str:
        """Wrap a command with proxychains if target is tunneled."""
        if self.tunneled:
            if cmd.strip().startswith("proxychains"):
                return cmd
            return f"proxychains -q {cmd}"
        return cmd

    def nmap_flags(self) -> str:
        """Return extra nmap flags needed for tunneled targets."""
        if self.tunneled:
            return "-sT -Pn"
        return ""

    def nmap_cmd(self, args: str) -> str:
        """Build a complete nmap command, tunnel-aware."""
        flags = self.nmap_flags()
        base = f"nmap {flags} {args}".strip() if flags else f"nmap {args}"
        return self.wrap(base)

    def nxc_cmd(self, protocol: str, target: str, auth: str, extra: str = "") -> str:
        """Build a nxc command, tunnel-aware."""
        cmd = f"nxc {protocol} {target} {auth}"
        if extra:
            cmd += f" {extra}"
        return self.wrap(cmd)

    def impacket_cmd(self, tool: str, args: str) -> str:
        """Build an impacket command, tunnel-aware."""
        return self.wrap(f"impacket-{tool} {args}")

    def get_proxy(self) -> Optional[Tuple[str, str, int]]:
        """Return (type, host, port) of the detected proxy, or None."""
        return self.proxy

    def patch_sockets(self) -> bool:
        """Monkey-patch Python's socket module to route all connections through SOCKS.

        After calling this, impacket, ldap3, and any library using socket.socket()
        will transparently tunnel through the detected SOCKS proxy.

        Returns True if patching succeeded, False if no proxy or PySocks missing.
        """
        if not self.proxy:
            return False
        proxy_type, proxy_host, proxy_port = self.proxy

        try:
            import socks
        except ImportError:
            return False

        stype = socks.SOCKS5
        if "socks4" in proxy_type:
            stype = socks.SOCKS4

        socks.set_default_proxy(stype, proxy_host, proxy_port)
        _stdlib_socket.socket = socks.socksocket
        return True

    def needs_proxychains(self) -> bool:
        """Check if tools need proxychains and it's NOT currently active."""
        return self.tunneled and not _detect_proxychains_active()

    def status_str(self) -> str:
        """Human-readable one-liner about tunnel status."""
        if not self.tunneled:
            return "direct (no tunnel)"
        parts = [f"tunneled via {self.source}"]
        if self.proxy:
            parts.append(f"proxy={self.proxy[0]}://{self.proxy[1]}:{self.proxy[2]}")
        if self.subnet:
            parts.append(f"subnet={self.subnet}")
        return ", ".join(parts)


# ── State file ──────────────────────────────────────────────────────────

def _load_state() -> dict:
    """Load Hyperdrive state file with TTL cache."""
    global _state_cache, _state_cache_time
    import time
    now = time.monotonic()
    if _state_cache is not None and (now - _state_cache_time) < _CACHE_TTL:
        return _state_cache
    try:
        _state_cache = json.loads(Path(STATE_FILE).read_text())
        _state_cache_time = now
        return _state_cache
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        _state_cache = {}
        _state_cache_time = now
        return {}


def _ip_in_subnet(ip_str: str, subnet_str: str) -> bool:
    """Check if an IP address falls within a CIDR subnet."""
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(subnet_str, strict=False)
    except ValueError:
        return False


# ── Public API ──────────────────────────────────────────────────────────

def tunnel_ctx(target: str) -> TunnelContext:
    """Get tunnel context for a target. Auto-detects Hyperdrive, env vars, SOCKS ports.

    Detection priority:
    1. TUNNEL_PROXY env var (explicit: always tunneled)
    2. Hyperdrive state file (target IP in routed subnet)
    3. Probe common SOCKS ports (chisel, SSH -D, etc.)

    For #3, we can't know which subnets are routed, so we only report the proxy.
    The caller decides whether to use it.
    """
    # 1. Explicit env var proxy
    env_proxy = _detect_proxy_env()
    if env_proxy:
        return TunnelContext(
            tunneled=True, proxy=env_proxy, source="env",
            all_routes=get_routes(),
        )

    # 2. Hyperdrive state file
    state = _load_state()
    if state:
        routes = list(state.get("routes", []))
        for dp in state.get("double_pivots", []):
            s = dp.get("subnet")
            if s and s not in routes:
                routes.append(s)

        if routes:
            # Resolve target
            ip_str = target
            try:
                ipaddress.ip_address(target)
            except ValueError:
                import socket
                try:
                    ip_str = socket.gethostbyname(target)
                except socket.gaierror:
                    if routes:
                        return TunnelContext(
                            tunneled=True, interface=state.get("interface", "ligolo"),
                            subnet=routes[0], all_routes=routes,
                            proxy=("socks5", "127.0.0.1", 1080),
                            proxy_pid=state.get("proxy_pid"),
                            session_count=len(state.get("sessions", [])),
                            source="hyperdrive",
                        )
                    return TunnelContext(all_routes=routes)

            # Check subnets
            matched = ""
            matched_iface = state.get("interface", "ligolo")
            for route in routes:
                if _ip_in_subnet(ip_str, route):
                    matched = route
                    break

            if matched:
                for dp in state.get("double_pivots", []):
                    if dp.get("subnet") == matched:
                        matched_iface = dp.get("interface", "ligolo2")
                        break

                return TunnelContext(
                    tunneled=True, interface=matched_iface, subnet=matched,
                    all_routes=routes, proxy=("socks5", "127.0.0.1", 1080),
                    proxy_pid=state.get("proxy_pid"),
                    session_count=len(state.get("sessions", [])),
                    source="hyperdrive",
                )

    # 3. Probe local SOCKS ports (chisel, SSH -D, etc.)
    probed = _detect_proxy_ports()
    if probed:
        return TunnelContext(
            tunneled=True, proxy=probed, source="probe",
            all_routes=get_routes(),
        )

    return TunnelContext()


def tunnel_ctx_manual(proxy_url: str, target: str = "") -> TunnelContext:
    """Create a tunnel context from an explicit proxy URL.

    Use this when the user passes --proxy socks5://127.0.0.1:1080.
    """
    parsed = _parse_proxy_url(proxy_url)
    if not parsed:
        return TunnelContext()
    return TunnelContext(tunneled=True, proxy=parsed, source="manual")


def is_tunneled(target: str) -> bool:
    """Quick check: is this target behind any detected tunnel?"""
    return tunnel_ctx(target).tunneled


def get_routes() -> List[str]:
    """Get all currently routed subnets from Hyperdrive."""
    state = _load_state()
    routes = list(state.get("routes", []))
    for dp in state.get("double_pivots", []):
        s = dp.get("subnet")
        if s and s not in routes:
            routes.append(s)
    return routes


def tunnel_status_line() -> str:
    """One-line tunnel status for tool banners."""
    state = _load_state()
    if not state:
        # Check for non-Hyperdrive proxy
        proxy = detect_proxy()
        if proxy:
            return f"proxy: {proxy[0]}://{proxy[1]}:{proxy[2]}"
        return ""
    routes = state.get("routes", [])
    pid = state.get("proxy_pid")
    sessions = state.get("sessions", [])
    if not pid:
        return ""
    parts = [f"tunnel: {len(sessions)} session(s)"]
    if routes:
        parts.append(f"routes: {', '.join(routes)}")
    return " | ".join(parts)
