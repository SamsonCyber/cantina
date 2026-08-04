"""
findings.py - Shared findings schema for the OSCP toolkit.

Every tool writes findings in the same JSONL format (one JSON object per line).
Multiple tools can append to the same file. A report generator reads them all.

Schema:
    {
        "host":        "10.10.10.5",
        "port":        445,
        "finding":     "Null session SMB listing allowed",
        "severity":    "CRITICAL",
        "category":    "SMB",
        "evidence":    "smbclient returned 3 readable shares",
        "exploit_cmd": "smbclient //10.10.10.5/Data -N",
        "tool":        "jawa",
        "timestamp":   "2026-03-28T14:30:00"
    }

Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO

Usage (any tool):
    from findings import FindingsCollector
    fc = FindingsCollector(tool="jawa", host="10.10.10.5", output="findings.jsonl")
    fc.add("HIGH", "SMB", "Null session allowed", port=445,
           evidence="3 readable shares", exploit_cmd="smbclient //target/Data -N")
    fc.flush()   # writes to disk
    fc.close()   # final flush + close

    # Read back:
    from findings import load_findings
    for f in load_findings("findings.jsonl"):
        print(f["severity"], f["finding"])

    # Filter:
    crits = [f for f in load_findings("findings.jsonl") if f["severity"] == "CRITICAL"]
"""

import io
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


# ── Auto-engage: every tool auto-logs to ~/.psk/engage/ ──────────────────

DEFAULT_ENGAGE_DIR = os.path.join(str(Path.home()), ".psk", "engage")


class _Tee:
    """Transparent stdout wrapper that captures everything printed."""
    def __init__(self, original):
        self.original = original
        self.buffer = io.StringIO()
    def write(self, text):
        self.original.write(text)
        self.buffer.write(text)
    def flush(self):
        self.original.flush()
    def getvalue(self):
        return self.buffer.getvalue()
    # Forward any other attribute to original (isatty, fileno, etc.)
    def __getattr__(self, name):
        return getattr(self.original, name)


_active_tee = None
_engage_tool = None
_engage_target = None
_engage_dir = None


def engage_start(tool_name, target="local", engage_dir=None):
    """Call at the start of main(). Starts capturing stdout for auto-logging.

    Args:
        tool_name: e.g. "jawa", "ackbar", "maul"
        target: IP or hostname being scanned (used in filename)
        engage_dir: override directory (default: ~/.psk/engage/)
    """
    global _active_tee, _engage_tool, _engage_target, _engage_dir

    # Check for --no-log flag anywhere in sys.argv
    if "--no-log" in sys.argv:
        return

    _engage_dir = engage_dir or os.environ.get("PSK_ENGAGE_DIR", DEFAULT_ENGAGE_DIR)
    _engage_tool = tool_name
    _engage_target = re.sub(r"[:/\\]", "_", str(target))  # sanitize for filename
    _active_tee = _Tee(sys.stdout)
    sys.stdout = _active_tee

    # Register atexit handler so logs are written even on sys.exit() or crash
    import atexit
    atexit.register(engage_end)


def engage_end():
    """Writes captured output to engage dir. Safe to call multiple times.
    Returns the path written, or None if logging was disabled/already flushed."""
    global _active_tee, _engage_tool, _engage_target, _engage_dir

    if _active_tee is None:
        return None

    # Restore stdout
    sys.stdout = _active_tee.original
    captured = _active_tee.getvalue()

    # Strip ANSI codes for clean file
    clean = re.sub(r"\033\[[0-9;]*m", "", captured)

    # Write to engage dir
    os.makedirs(_engage_dir, exist_ok=True)
    filename = f"{_engage_tool}_{_engage_target}.txt"
    filepath = os.path.join(_engage_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(clean)

    print(f"  \033[2m[engage] {filepath}\033[0m")

    # Reset
    _active_tee = None
    return filepath


class FindingsCollector:
    """Collects findings and writes them as JSONL (one JSON object per line)."""

    def __init__(self, tool, host="", output=""):
        self.tool = tool
        self.host = host
        self.output = output
        self.findings = []
        self._file = None
        if output:
            self._file = open(output, "a", encoding="utf-8")

    def add(self, severity, category, finding, port=0, evidence="", exploit_cmd=""):
        """Add a finding. Appends to memory and optionally to file immediately."""
        entry = {
            "host": self.host,
            "port": port,
            "finding": finding,
            "severity": severity.upper(),
            "category": category,
            "evidence": evidence,
            "exploit_cmd": exploit_cmd,
            "tool": self.tool,
            "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        }
        self.findings.append(entry)
        # Stream to file immediately (crash-safe, no findings lost)
        if self._file:
            self._file.write(json.dumps(entry) + "\n")
            self._file.flush()
        return entry

    def flush(self):
        """Flush file buffer to disk."""
        if self._file:
            self._file.flush()

    def close(self):
        """Final flush and close."""
        if self._file:
            self._file.flush()
            self._file.close()
            self._file = None

    def count(self, severity=None):
        """Count findings, optionally filtered by severity."""
        if severity:
            return len([f for f in self.findings if f["severity"] == severity.upper()])
        return len(self.findings)

    @property
    def crits(self):
        return [f for f in self.findings if f["severity"] == "CRITICAL"]

    @property
    def highs(self):
        return [f for f in self.findings if f["severity"] == "HIGH"]

    @property
    def warnings(self):
        return [f for f in self.findings if f["severity"] in ("MEDIUM", "WARNING")]

    def summary_dict(self):
        """Return a summary dict for JSON export."""
        return {
            "tool": self.tool,
            "host": self.host,
            "total": len(self.findings),
            "critical": self.count("CRITICAL"),
            "high": self.count("HIGH"),
            "medium": self.count("MEDIUM"),
            "low": self.count("LOW"),
            "info": self.count("INFO"),
        }

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ── Vader auto-registration ────────────────────────────────────────────
# Any tool can call these to auto-populate vader's holocron.json.
# Writes are atomic (load-modify-save) and deduped. Silent on failure.

HOLOCRON_PATH = os.path.join(str(Path.home()), ".psk", "holocron.json")

def _holo_load():
    try:
        if os.path.exists(HOLOCRON_PATH):
            with open(HOLOCRON_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        pass
    return {"credentials": [], "hosts": [], "attempts": []}

def _holo_save(data):
    try:
        os.makedirs(os.path.dirname(HOLOCRON_PATH), exist_ok=True)
        with open(HOLOCRON_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass

def vader_log_host(ip, hostname="", os_type="", ports=None, source=""):
    """Auto-register a host in vader's holocron. Deduped, silent on failure.

    Call this whenever a tool discovers a new host:
        vader_log_host("10.10.10.5", hostname="DC01", os_type="windows",
                       ports=[88, 445, 389], source="cantina")
    """
    if not ip:
        return
    try:
        data = _holo_load()
        existing = next((h for h in data["hosts"] if h["ip"] == ip), None)
        if existing:
            if hostname and not existing.get("hostname"):
                existing["hostname"] = hostname
            if os_type and not existing.get("os"):
                existing["os"] = os_type
            if ports:
                current = set(existing.get("ports", []))
                current.update(int(p) for p in ports)
                existing["ports"] = sorted(current)
        else:
            data["hosts"].append({
                "ip": ip, "hostname": hostname, "os": os_type,
                "ports": sorted(int(p) for p in ports) if ports else [],
                "status": "unowned", "proof_hash": "",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        _holo_save(data)
    except Exception:
        pass  # never crash a tool over tracking

def vader_log_cred(username, password="", hash_val="", host="", source="", access=""):
    """Auto-register a credential in vader's holocron. Deduped, silent on failure.

    Call this whenever a tool discovers credentials:
        vader_log_cred("admin", password="Password1", host="10.10.10.5", source="jawa")
        vader_log_cred("svc_sql", hash_val="aad3b435...", host="10.10.10.5", source="leia")
    """
    if not username:
        return
    try:
        data = _holo_load()
        # Dedup check
        for c in data["credentials"]:
            if c["username"] == username:
                if password and c.get("password") == password:
                    return
                if hash_val and c.get("hash") == hash_val:
                    return
        data["credentials"].append({
            "username": username, "password": password or "",
            "hash": hash_val or "", "host": host,
            "source_tool": source, "access_level": access,
            "notes": "", "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        _holo_save(data)
    except Exception:
        pass  # never crash a tool over tracking


def load_findings(path):
    """Load findings from a JSONL file. Returns list of dicts."""
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return findings


def load_findings_by_host(path):
    """Group findings by host. Returns {host: [findings]}."""
    by_host = {}
    for f in load_findings(path):
        host = f.get("host", "unknown")
        by_host.setdefault(host, []).append(f)
    return by_host


def load_findings_by_tool(path):
    """Group findings by tool. Returns {tool: [findings]}."""
    by_tool = {}
    for f in load_findings(path):
        tool = f.get("tool", "unknown")
        by_tool.setdefault(tool, []).append(f)
    return by_tool


def merge_findings(*paths):
    """Merge multiple JSONL files into a single sorted list."""
    all_findings = []
    for path in paths:
        all_findings.extend(load_findings(path))
    all_findings.sort(key=lambda f: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.get("severity", "INFO"), 5),
        f.get("host", ""),
        f.get("port", 0),
    ))
    return all_findings


# ── Quick test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    # Write some findings
    tmp = os.path.join(tempfile.gettempdir(), "test_findings.jsonl")
    with FindingsCollector(tool="demo", host="10.10.10.5", output=tmp) as fc:
        fc.add("CRITICAL", "SMB", "Null session allowed", port=445,
               evidence="smbclient listed 3 shares", exploit_cmd="smbclient //10.10.10.5/Data -N")
        fc.add("HIGH", "FTP", "Anonymous login", port=21,
               evidence="ftp-anon script confirmed", exploit_cmd="ftp 10.10.10.5")
        fc.add("INFO", "SSH", "Password auth enabled", port=22)

    # Append from another tool
    with FindingsCollector(tool="cantina", host="10.10.10.5", output=tmp) as fc:
        fc.add("CRITICAL", "CVE", "CVE-2021-34527 PrintNightmare", port=445,
               evidence="nmap vuln script", exploit_cmd="CVE-2021-34527.py 10.10.10.5")

    # Read back
    findings = load_findings(tmp)
    print(f"Loaded {len(findings)} findings from {tmp}")
    for f in findings:
        print(f"  [{f['severity']:<8}] {f['tool']:<8} {f['host']}:{f['port']} {f['finding']}")

    print()
    print("By host:", {k: len(v) for k, v in load_findings_by_host(tmp).items()})
    print("By tool:", {k: len(v) for k, v in load_findings_by_tool(tmp).items()})

    # Cleanup
    os.remove(tmp)
    print("OK")
