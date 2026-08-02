#!/usr/bin/env python3
"""
Cantina v1.3.3 - OSCP Network Reconnaissance Orchestrator

Automated port discovery, service enumeration, and recon tool dispatch.
Runs nmap scans in parallel where possible, auto-dispatches service-specific
tools based on what's found, and produces structured JSON alongside clean
terminal output.

v1.1: dual -oN/-oX nmap writes, XML+text port merge on resume, offline
scorecard (cantina_score / cantina_bench) for scan-to-scan metric deltas.
v1.2: deep long-running background mode (-t deep --background), phase
status file so short tools can run while deep recon continues.
v1.3: concurrent multi-target + timeouts; force-services/ports; per-port
recon layout + _commands.log; vhost/subdomain enum; Telnet/ES/Kibana;
onesixtyone; enum4linux-ng preference; dirbust CLI; decision branches.
v1.4: first-class enum plugin model (discover/register/run) + --list-plugins.
v1.3.3: unify HTTP_PORTS for select_service_type; shutil.which/geteuid;
ftp name match for alt-FTP service labels.

Usage:
    python3 cantina.py TARGET
    python3 cantina.py TARGET -t full
    python3 cantina.py TARGET -t all
    python3 cantina.py 10.10.10.0/24 -t network
    python3 cantina.py TARGET -t all -o /path/to/output
    python3 cantina.py TARGET -t all --skip-recon
    python3 cantina.py TARGET -t all --resume
    python3 cantina.py -T targets.txt -t all --max-workers 3
    python3 cantina.py TARGET -t all --config cantina.toml
    python3 cantina.py TARGET -t recon --force-services tcp/80/http tcp/445/smb
    python3 cantina.py TARGET -t recon --ports 80,443,445

Scan Types:
    quick     Top 1000 ports + scripts (default, ~2 min)
    full      All 65535 TCP ports + scripts on new ports (~10 min)
    udp       Top 200 UDP ports (~5 min)
    vuln      CVE + vuln scripts on discovered ports (~5 min)
    recon     Service-specific tool dispatch (~5-15 min)
    network   Sweep a subnet for live hosts (~30 sec)
    all       quick → full → udp → vuln → recon in parallel where possible

Flags (selected):
    -T FILE            Multi-target mode: file with one target per line
    --max-workers N    Concurrent multi-target workers (default 3)
    --timeout MIN      Global run timeout in minutes
    --target-timeout MIN  Per-target timeout in minutes
    --force-services   Seed known services (tcp/80/http …); skip rediscovery
    --ports            Known open ports (skip full rediscovery)
    --config FILE      Plugin config (cantina.toml) for custom tool commands
    --dirbust-tool     feroxbuster|ffuf|gobuster
    --dirbust-wordlist Wordlist path(s)
    --dirbust-threads  Dirbust thread count
    --dirbust-ext      Extensions (no dots, comma-separated)
    --vhost-domain     Base host for virtual-host enum
    --subdomain-domain Base domain for subdomain enum

Outputs (under each per-target directory):
    nmap/              raw nmap -oN/-oX files (one per scan phase)
    recon/             service recon (also recon/tcp80/, recon/udp53/, …)
    _commands.log      audit log of every automated command run
    cantina.log        full session log
    cantina.json       structured summary (when -j is set)
    _patterns.log      pattern-matched findings (creds, IPs, etc.)
    report.html        self-contained HTML report (deterministic, no AI, no network)

Legal: Enumeration only. No exploitation. OSCP exam safe. The HTML report is
generated locally with pure Python templating, no LLM calls, no network calls.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
try:
    from findings import FindingsCollector, engage_start, engage_end, vader_log_host
except ImportError:
    class FindingsCollector:
        def __init__(self, *a, **kw): pass
        def __getattr__(self, name): return lambda *a, **kw: None
    def engage_start(*a, **kw): pass
    def engage_end(): pass
    def vader_log_host(*a, **kw): pass

try:
    from tui import UI, C, BOX, badge, progress_bar, table, Spinner
except ImportError:
    class _FallbackColor:
        def __getattr__(self, name): return ''
    C = _FallbackColor()
    BOX = {'tl': '+', 'tr': '+', 'bl': '+', 'br': '+', 'h': '-', 'v': '|',
           'lt': '+', 'rt': '+', 'tt': '+', 'bt': '+', 'x': '+',
           'bullet': '*', 'arrow': '>', 'check': '+', 'cross': 'x',
           'warn': '!', 'bar_full': '#', 'bar_half': '=', 'bar_empty': '.', 'dot': '.', 'tri': '>'}
    def badge(*a, **kw): return ""
    def progress_bar(*a, **kw): return ""
    def table(headers, rows, **kw): return []
    class Spinner:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def update(self, *a): pass
    class UI:
        def __init__(self, *a, **kw): pass
        def __getattr__(self, name): return lambda *a, **kw: None

VERSION = "1.3.3"

# Shared HTTP/HTTPS port sets (select_service_type + Scanner must stay in sync)
HTTP_PORTS = frozenset({
    80, 81, 82, 443,
    591, 631, 1080, 1443, 1880,
    2080, 2375, 2376,
    3000, 3128,
    4443, 4444, 4646,
    5000, 5001, 5480,
    6080,
    7001, 7080, 7474, 7687,
    8000, 8001, 8006, 8007, 8008,
    8010, 8042, 8065, 8069, 8080, 8081, 8083, 8088,
    8090, 8091, 8111, 8118, 8123, 8161, 8181, 8200,
    8443, 8444, 8500, 8530, 8531, 8585,
    8765, 8800, 8834, 8880, 8888, 8889, 8983,
    9000, 9001, 9002, 9080, 9090, 9091, 9092,
    9443,
    9981, 9999, 10000, 10250, 10444,
    11434,
})
# 88 = Kerberos (not HTTP). 9200/9300 = Elasticsearch. 5601 = Kibana.
# Those stay out of HTTP_PORTS and are classified in select_service_type first.
HTTPS_PORTS = frozenset({443, 5480, 8443, 8444, 8531, 9443})

# Per-thread runtime context (multi-target workers must not stomp each other)
_tls = threading.local()
_ui_lock = threading.Lock()
# Shared multi-target global clock start only (immutable after run start); not a sink
_shared_global_start = None
_shared_global_timeout_sec = None


def get_command_audit():
    return getattr(_tls, "command_audit", None)


def set_command_audit(audit):
    _tls.command_audit = audit


def get_deadline_clock():
    return getattr(_tls, "deadline_clock", None)


def set_deadline_clock(clock):
    _tls.deadline_clock = clock


def get_collected_cmds():
    cmds = getattr(_tls, "collected_cmds", None)
    if cmds is None:
        cmds = []
        _tls.collected_cmds = cmds
    return cmds


def reset_collected_cmds():
    _tls.collected_cmds = []
    _tls.current_section = "General"


def get_current_section():
    return getattr(_tls, "current_section", "General")


def set_current_section(name):
    _tls.current_section = name or "General"


# ── Output (via shared TUI) ──────────────────────────────────────────
ui = UI(title="CANTINA", version=VERSION)

def section(t):
    set_current_section(t)
    ui.section(t)
def subsection(t):
    set_current_section(t)
    ui.subsection(t)
def crit(m):       ui.crit(m)
def warn(m):       ui.warn(m)
def good(m):       ui.good(m)
def info(m):       ui.info(m)
def dimm(m):       ui.dim(m)
def found(m):      ui.found(m)
def cmd_hint(m):
    get_collected_cmds().append((get_current_section(), m))
    ui.cmd(m)
def out(msg=""):   ui._write(msg)

W = C.W       # White bold
O = C.Y       # Orange
D = C.D       # Dim
R = C.RST     # Reset
CY = C.C      # Cyan

BANNER_LINES = [
    f"{D}⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈{R}",
    f"{D}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣀⣸⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠴⠾⠿⠿⠿⠛⠋⠁⠀⣠⣴⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣄⣀⣀⣀⣀⣀⣤⣤⣴⠶⠛⢋⣡⣴⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣬⣉⣉⣉⣉⡟⣁⠀⠀⠈⠙⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⡀⠛⠀⠀⠀⠀⣿⣿⠋⠉⠙⢿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠀⣀⣴⣿⣇⠀⠀⠀⣸⣿⣿⡿⠀⠀⠀⠀⠀⠀{W}C A N T I N A{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡴⠟⠛⣁⠤⠂⠀⠀⠀⠀⠀{W}Network Recon v{{version}}{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠛⠛⣉⣡⠤⠒⠋⠁⢀⣀⠀⠀⠀⠀⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⠬⣉⣉⣉⣉⣠⠤⠤⠤⠴⠒⠚⠉⠁⠀⠀⠀⣤⣾⣿⣿⣿⣶⣄⡀⠀⠀{D}\"You'll never find a more{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣦⣤⣤⣤⣤⣤⣤⣤⣤⣴⣶⣶⣦⡀⠀⠈⠙⢿⣿⠋⠛⣿⣿⣦⡀{D} wretched hive of scans{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠿⠛⠉⠉⠉⠉⠉⠛⠿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⢿⣿⣿⣿{D} and enumery.\"{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠟⠁⢀⣠⣤⣤⣤⣄⡀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⠀⠀⠀⠉⠉{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⣴⣿⣿⣿⣿⣿⠟⠀⢀⡀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣦⣤⣀{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠇⠀⠀⢹⣿⣿⣿⣿⣿⣤⣴⣿⣿⡄⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⣿⣦⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⠻{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⢿⣿⡿⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⠀⠀⠀{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⡀⠸⣿⡿⢿⣿⣿⣿⣿⣿⣄⠀⠈⠁⠀⠀⢀⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⣠⣤⣶{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣧⠀⠙⠀⢰⣿⣿⣿⣿⣿⣿⡷⠀⠀⠀⠀⣼⣿⣿⣿⣿⡟⠁⠀⠀⣠⡀⠀⢻⣿⣿{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣷⡀⠀⠘⠛⠿⠿⠿⠛⠉⠀⠀⠀⢀⣾⣿⣿⣿⣿⠏⠀⠀⢀⣴⣿⣷⣤⣼⣿⣿{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣦⣄⡀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⡏⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣷⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⠋{R}",
    f"{O}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠘⠛⠛⣹⣿⣿⣿⠟⠁⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢠⣶⣿⣿⡿⠟⠁⠀⠀⠀{R}",
    f"{W}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠈⠻⠿⠛⠉⠀⠀⠀⠀⠀{R}",
    f"{D}⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠛⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀{R}",
]

def show_banner():
    for line in BANNER_LINES:
        ui._write(line.format(version=VERSION))


# ── Runner ──────────────────────────────────────────────────────────────

def _effective_timeout(timeout):
    """Cap requested timeout by thread-local DeadlineClock. Raises TimeoutError if expired."""
    clock = get_deadline_clock()
    if clock is None:
        return timeout
    return clock.cap_timeout(timeout)


def _audit_command(cmd, rc, duration_s, note=""):
    audit = get_command_audit()
    if audit is not None:
        try:
            audit.log(cmd, rc=rc, duration_s=duration_s, note=note)
        except Exception:
            pass


def run(cmd, timeout=600):
    """Run a command, return (stdout, stderr, returncode).

    Deadline expiry raises TimeoutError (hard abandon) after audit note.
    Process timeouts still return soft [TIMEOUT] rc.
    """
    t0 = time.time()
    try:
        timeout = _effective_timeout(timeout)
    except TimeoutError as e:
        _audit_command(cmd, rc=124, duration_s=0, note="deadline_expired")
        raise TimeoutError("deadline expired") from e
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        _audit_command(cmd, rc=r.returncode, duration_s=time.time() - t0)
        # Mid-run global/target budget may have elapsed while subprocess ran
        clock = get_deadline_clock()
        if clock is not None and clock.expired():
            _audit_command(cmd, rc=124, duration_s=time.time() - t0, note="deadline_expired_after")
            raise TimeoutError("deadline expired")
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except TimeoutError:
        raise
    except subprocess.TimeoutExpired:
        _audit_command(cmd, rc=124, duration_s=time.time() - t0, note="timeout")
        return "", "[TIMEOUT]", 1
    except Exception as e:
        _audit_command(cmd, rc=1, duration_s=time.time() - t0, note=str(e))
        return "", f"[ERROR: {e}]", 1

def run_live(cmd, timeout=600):
    """Run a command with live stdout passthrough, return full stdout.

    Deadline expiry raises TimeoutError (hard abandon) after audit note.
    """
    output_lines = []
    t0 = time.time()
    try:
        timeout = _effective_timeout(timeout)
    except TimeoutError as e:
        _audit_command(cmd, rc=124, duration_s=0, note="deadline_expired")
        raise TimeoutError("deadline expired") from e
    try:
        proc = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for line in proc.stdout:
            line = line.rstrip()
            output_lines.append(line)
            with _ui_lock:
                ui._write(f"  {C.D}{line}")
        proc.wait(timeout=timeout)
        _audit_command(cmd, rc=proc.returncode, duration_s=time.time() - t0)
        clock = get_deadline_clock()
        if clock is not None and clock.expired():
            _audit_command(cmd, rc=124, duration_s=time.time() - t0, note="deadline_expired_after")
            raise TimeoutError("deadline expired")
        return "\n".join(output_lines), proc.returncode
    except TimeoutError:
        raise
    except subprocess.TimeoutExpired:
        proc.kill()
        _audit_command(cmd, rc=124, duration_s=time.time() - t0, note="timeout")
        return "\n".join(output_lines), 1
    except Exception as e:
        _audit_command(cmd, rc=1, duration_s=time.time() - t0, note=str(e))
        return str(e), 1

# Process-wide PATH lookup cache (tool presence does not change mid-scan).
_TOOL_EXISTS_CACHE: dict = {}


def clear_tool_exists_cache():
    """Reset PATH cache (tests / rare PATH changes)."""
    _TOOL_EXISTS_CACHE.clear()


def tool_exists(name):
    """True if executable is on PATH (no shell). Cached per process."""
    if not name:
        return False
    key = str(name)
    if key in _TOOL_EXISTS_CACHE:
        return _TOOL_EXISTS_CACHE[key]
    found = shutil.which(key) is not None
    _TOOL_EXISTS_CACHE[key] = found
    return found

def is_root():
    """True when process is euid 0. False on platforms without geteuid."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def nmap_script_available(script_name):
    """Return True if nmap can load the named NSE script (registered in script.db)."""
    try:
        proc = subprocess.run(
            ["nmap", "--script-help", script_name],
            capture_output=True, text=True, timeout=10
        )
        # nmap exits non-zero AND prints to stderr when a script category/name doesn't match.
        out_combined = (proc.stdout or "") + (proc.stderr or "")
        if "did not match" in out_combined or "no scripts were specified" in out_combined.lower():
            return False
        # Successful lookup: stdout contains "Categories:" or the script name in the help text
        return script_name in out_combined
    except Exception:
        return False


# ── Decision branches (enum-only, OSCP-legal) ───────────────────────────
# Pure helpers: probe evidence → which recon tools to run. No exploitation.
# Heavy tools (dirbust, nikto, enum4linux) only when signals justify them.

# High-value HTTP ports: deeper wordlists / nikto when evidence says real app
_HTTP_HIGH_VALUE = frozenset({80, 443, 3000, 8000, 8080, 8443, 8888})

# Credential-spray / brute tools are never auto-selected (hints only elsewhere)
_BANNED_AUTO_TOOLS = frozenset({
    "hydra", "medusa", "patator", "crowbar", "ncrack",
    "redis-brute", "vnc-brute", "snmp-brute",
})


def parse_http_probe(headers_text, body_snip=""):
    """Parse curl -I / body probe into signal dict (pure, offline-testable)."""
    headers_text = headers_text or ""
    body_snip = body_snip or ""
    status = None
    m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", headers_text)
    if m:
        status = int(m.group(1))
    server = ""
    m = re.search(r"(?im)^Server:\s*(.+)$", headers_text)
    if m:
        server = m.group(1).strip()
    content_type = ""
    m = re.search(r"(?im)^Content-Type:\s*([^\r\n;]+)", headers_text)
    if m:
        content_type = m.group(1).strip().lower()
    powered = ""
    m = re.search(r"(?im)^X-Powered-By:\s*(.+)$", headers_text)
    if m:
        powered = m.group(1).strip()
    lower_h = headers_text.lower()
    lower_b = body_snip.lower()
    looks_http = status is not None or "http/" in lower_h[:40]
    has_html = (
        "text/html" in content_type
        or "<html" in lower_b
        or "<!doctype html" in lower_b
        or "<title" in lower_b
    )
    has_json = "application/json" in content_type or (
        body_snip.strip().startswith("{") and ":" in body_snip[:200]
    )
    body_len = len(body_snip.strip())
    tiny_banner = body_len > 0 and body_len < 80 and not has_html and not has_json
    interesting_status = status in (200, 201, 204, 301, 302, 307, 308, 401, 403, 500)
    # Real web app: HTTP response with content or auth wall, not a one-shot banner
    real_app = bool(
        looks_http
        and interesting_status
        and (has_html or has_json or body_len >= 80 or status in (401, 403))
        and not tiny_banner
    )
    cms = None
    blob = f"{headers_text}\n{body_snip}\n{powered}".lower()
    if "wordpress" in blob or "wp-content" in blob or "wp-includes" in blob:
        cms = "wordpress"
    elif "joomla" in blob:
        cms = "joomla"
    elif "drupal" in blob:
        cms = "drupal"
    elif "juice" in blob and ("shop" in blob or "owasp" in blob):
        cms = "juice-shop"
    return {
        "looks_http": looks_http,
        "status": status,
        "server": server,
        "content_type": content_type,
        "powered_by": powered,
        "has_html": has_html,
        "has_json": has_json,
        "body_len": body_len,
        "tiny_banner": tiny_banner,
        "real_app": real_app,
        "cms": cms,
    }


def decide_http_actions(signals, *, depth="normal", port=80, tools_present=None):
    """Decide which HTTP enum tools to run. Enumeration only.

    depth: 'quick' | 'normal' | 'deep'
    tools_present: optional set of tool names available; None = assume all.
    """
    tools_present = tools_present  # None means do not filter by presence
    depth = (depth or "normal").lower()
    port = int(port)
    high = port in _HTTP_HIGH_VALUE
    actions = []

    def add(tool, run, reason, weight="light"):
        if tool in _BANNED_AUTO_TOOLS:
            return
        # Speed: never schedule heavy tools in quick depth
        if run and weight == "heavy" and depth == "quick":
            actions.append({
                "tool": tool, "run": False,
                "reason": f"skip heavy in depth=quick ({reason})",
                "weight": weight,
            })
            return
        if tools_present is not None and run and tool not in tools_present:
            actions.append({
                "tool": tool, "run": False,
                "reason": f"skip: {tool} not installed ({reason})",
                "weight": weight,
            })
            return
        actions.append({"tool": tool, "run": bool(run), "reason": reason, "weight": weight})

    if not signals.get("looks_http"):
        add("http_probe", True, "port open but no HTTP response — record only")
        add("whatweb", False, "not HTTP")
        add("jarjar", False, "not HTTP")
        add("dirbust", False, "not HTTP")
        add("nikto", False, "not HTTP")
        add("wpscan", False, "not HTTP")
        add("sslscan", False, "not HTTP")
        return actions

    add("http_probe", True, f"HTTP {signals.get('status')} server={signals.get('server') or '?'}")
    add("whatweb", True, "fingerprints stack on confirmed HTTP")
    add("jarjar", True, "toolkit HTTP enum on confirmed HTTP")

    # Dirbust / nikto only on real apps, not one-shot fake banners
    if signals.get("tiny_banner") and not signals.get("real_app"):
        add("dirbust", False, "tiny banner only — skip heavy web enum")
        add("nikto", False, "tiny banner only — skip nikto")
    elif signals.get("real_app"):
        # Wordlist weight: common for normal; medium for deep or high-value
        if depth == "deep" or (depth == "normal" and high):
            wl = "medium"
        else:
            wl = "common"
        add(
            "dirbust", True,
            f"real web app (status={signals.get('status')}) wordlist={wl}",
            weight="heavy",
        )
        # Nikto is noisy/slow: deep always; normal only high-value ports
        if depth == "deep" or high:
            add("nikto", True, f"real app on port {port} (depth={depth})", weight="heavy")
        else:
            add("nikto", False, f"real app but port {port} not high-value in depth={depth}")
    else:
        add("dirbust", False, "HTTP but not a real app surface yet")
        add("nikto", False, "HTTP but not a real app surface yet")

    cms = signals.get("cms")
    if cms == "wordpress":
        add("wpscan", True, "WordPress signals in probe", weight="heavy")
    else:
        add("wpscan", False, f"no WordPress signal (cms={cms})")
    if cms == "joomla":
        add("joomscan", False, "Joomla detected — hint only (manual)")
    if cms == "drupal":
        add("droopescan", False, "Drupal detected — hint only (manual)")

    return actions


def decide_smb_actions(*, null_list_ok, shares_readable, access_denied):
    """SMB tool branches after null-session probe. Enum only (no spray)."""
    actions = []
    actions.append({
        "tool": "smbclient_null", "run": True,
        "reason": "always probe null session first", "weight": "light",
    })
    if null_list_ok or shares_readable:
        actions.append({
            "tool": "smbmap", "run": True,
            "reason": "null listing worked — map share perms", "weight": "light",
        })
        actions.append({
            "tool": "enum4linux", "run": True,
            "reason": "null/readable SMB — full OSCP-style enum", "weight": "heavy",
        })
        actions.append({
            "tool": "jawa", "run": True,
            "reason": "toolkit SMB enum on open shares", "weight": "heavy",
        })
    elif access_denied:
        actions.append({
            "tool": "smbmap", "run": False,
            "reason": "null denied — skip heavy share map", "weight": "light",
        })
        actions.append({
            "tool": "enum4linux", "run": False,
            "reason": "null denied — skip enum4linux (creds needed)", "weight": "heavy",
        })
        actions.append({
            "tool": "jawa", "run": True,
            "reason": "still try toolkit light path", "weight": "heavy",
        })
    else:
        actions.append({
            "tool": "smbmap", "run": True,
            "reason": "ambiguous null result — try smbmap", "weight": "light",
        })
        actions.append({
            "tool": "enum4linux", "run": True,
            "reason": "ambiguous — OSCP-standard SMB enum", "weight": "heavy",
        })
        actions.append({
            "tool": "jawa", "run": True,
            "reason": "toolkit SMB enum", "weight": "heavy",
        })
    actions.append({
        "tool": "nmap_smb_scripts", "run": True,
        "reason": "safe SMB discovery scripts (no exploit delivery)", "weight": "light",
    })
    return actions


def decide_ftp_actions(*, anon_allowed, has_version):
    """FTP branches: heavy listing only if anon allowed."""
    return [
        {
            "tool": "nmap_ftp_scripts", "run": True,
            "reason": "anon/bounce/syst fingerprint", "weight": "light",
        },
        {
            "tool": "banner_grab", "run": not has_version,
            "reason": "version missing — grab 220 banner" if not has_version else "version known",
            "weight": "light",
        },
        {
            "tool": "anon_list", "run": bool(anon_allowed),
            "reason": "anonymous login allowed — list + interesting files"
            if anon_allowed else "no anon — skip listing",
            "weight": "heavy",
        },
        {
            "tool": "anon_write_test", "run": bool(anon_allowed),
            "reason": "anon path — write probe (lab enum signal)"
            if anon_allowed else "no anon",
            "weight": "heavy",
        },
    ]


def decide_redis_actions(*, pong):
    """Redis: INFO only when unauth PONG. Never auto-brute."""
    return [
        {
            "tool": "redis_ping", "run": True,
            "reason": "probe unauthenticated access", "weight": "light",
        },
        {
            "tool": "redis_info", "run": bool(pong),
            "reason": "PONG — dump INFO (enum)" if pong else "no PONG — skip INFO",
            "weight": "light",
        },
        {
            "tool": "nmap_redis_info", "run": True,
            "reason": "nmap redis-info only (no redis-brute)", "weight": "light",
        },
    ]


def decide_snmp_actions(*, valid_community, onesixtyone_available=False):
    """SNMP: onesixtyone when available; deep walk only after known community."""
    return [
        {
            "tool": "community_probe", "run": True,
            "reason": "try common communities (public/private/…) — classic OSCP enum",
            "weight": "light",
        },
        {
            "tool": "onesixtyone",
            "run": bool(onesixtyone_available) and not valid_community,
            "reason": (
                "onesixtyone available — fast community discovery"
                if onesixtyone_available and not valid_community
                else (
                    "community already known — skip onesixtyone"
                    if valid_community
                    else "onesixtyone not installed"
                )
            ),
            "weight": "light",
        },
        {
            "tool": "snmpwalk_deep", "run": bool(valid_community),
            "reason": f"community '{valid_community}' valid — full walk"
            if valid_community else "no community yet — skip deep walk",
            "weight": "heavy",
        },
        {
            "tool": "snmp_check", "run": bool(valid_community),
            "reason": "valid community — snmp-check summary"
            if valid_community else "skip snmp-check without community",
            "weight": "heavy",
        },
        {
            "tool": "nmap_snmp_info", "run": True,
            "reason": "snmp-info scripts (not snmp-brute spray)", "weight": "light",
        },
    ]


def actions_to_run(actions):
    """Filter decided actions that should execute."""
    return [a for a in (actions or []) if a.get("run") and a.get("tool") not in _BANNED_AUTO_TOOLS]


def run_tasks_isolated(tasks, worker_fn, *, max_workers=4, inherit_tls=True):
    """Run independent tasks concurrently; isolate worker failures.

    tasks: iterable of opaque task items
    worker_fn(task) -> result (any)
    Returns list of dicts: {task, ok, result, error, duration_ms}
    Order matches completion order (not input order). Never raises for worker errors.

    inherit_tls: copy parent-thread command audit + deadline clock into each
    worker thread so concurrent recon still writes _commands.log and honors
    per-target deadlines (threading.local does not inherit automatically).
    """
    tasks = list(tasks or [])
    if not tasks:
        return []
    workers = max(1, min(int(max_workers or 1), len(tasks)))
    results = []
    # Capture parent-thread sinks before pool threads start
    parent_audit = get_command_audit() if inherit_tls else None
    parent_clock = get_deadline_clock() if inherit_tls else None

    def _wrapped(task):
        # Install parent sinks on this thread; restore prior values on exit so
        # sequential (workers=1) calls on the parent thread do not wipe TLS.
        prev_audit = get_command_audit()
        prev_clock = get_deadline_clock()
        if inherit_tls:
            set_command_audit(parent_audit)
            set_deadline_clock(parent_clock)
        t0 = time.perf_counter()
        try:
            out = worker_fn(task)
            ms = (time.perf_counter() - t0) * 1000.0
            return {
                "task": task,
                "ok": True,
                "result": out,
                "error": None,
                "duration_ms": round(ms, 3),
            }
        except Exception as e:
            ms = (time.perf_counter() - t0) * 1000.0
            return {
                "task": task,
                "ok": False,
                "result": None,
                "error": f"{type(e).__name__}: {e}",
                "duration_ms": round(ms, 3),
                "traceback": traceback.format_exc(limit=6),
            }
        finally:
            if inherit_tls:
                set_command_audit(prev_audit)
                set_deadline_clock(prev_clock)

    if workers == 1:
        for t in tasks:
            results.append(_wrapped(t))
        return results

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_wrapped, t): t for t in tasks}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                # Should not happen (_wrapped catches), but never abort siblings
                results.append({
                    "task": futs[fut],
                    "ok": False,
                    "result": None,
                    "error": f"future: {type(e).__name__}: {e}",
                    "duration_ms": 0.0,
                })
    return results


# ── Port Parsing ────────────────────────────────────────────────────────

def _port_record(port, proto="tcp", service="", version=""):
    """Normalize one open-port record for tcp_ports / scoring."""
    return {
        "port": int(port),
        "proto": proto or "tcp",
        "service": (service or "").strip(),
        "version": (version or "").strip(),
    }


# ── Gap helpers (v1.3): timeouts, force-services, vhost, service select ──

class DeadlineClock:
    """Global + per-target deadline. Pure timing; used by run()/workers.

    global_start may be shared across workers so concurrent hosts share one
    global budget without sharing mutable target_start (each worker begins_target).
    """

    def __init__(self, global_timeout_sec=None, target_timeout_sec=None, global_start=None):
        self.global_timeout_sec = (
            float(global_timeout_sec) if global_timeout_sec not in (None, 0) else None
        )
        self.target_timeout_sec = (
            float(target_timeout_sec) if target_timeout_sec not in (None, 0) else None
        )
        self.global_start = (
            float(global_start) if global_start is not None else time.monotonic()
        )
        self.target_start = None

    def begin_target(self):
        self.target_start = time.monotonic()

    def clone_for_target(self, target_timeout_sec=None):
        """New clock sharing global budget; own target timer."""
        t_to = self.target_timeout_sec if target_timeout_sec is None else target_timeout_sec
        c = DeadlineClock(
            global_timeout_sec=self.global_timeout_sec,
            target_timeout_sec=t_to,
            global_start=self.global_start,
        )
        c.begin_target()
        return c

    def remaining(self):
        rem = None
        if self.global_timeout_sec is not None:
            rem = self.global_timeout_sec - (time.monotonic() - self.global_start)
        if self.target_timeout_sec is not None and self.target_start is not None:
            t_rem = self.target_timeout_sec - (time.monotonic() - self.target_start)
            rem = t_rem if rem is None else min(rem, t_rem)
        return rem

    def expired(self):
        r = self.remaining()
        return r is not None and r <= 0

    def cap_timeout(self, requested):
        """Return min(requested, remaining). Raise TimeoutError if already expired."""
        if requested is None:
            requested = 600
        requested = float(requested)
        r = self.remaining()
        if r is None:
            return int(max(1, requested))
        if r <= 0:
            raise TimeoutError("deadline expired")
        return int(max(1, min(requested, r)))


class CommandAuditLog:
    """Append-only command audit under target outdir (_commands.log)."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        if not self.path.exists():
            self.path.write_text(
                "# cantina command audit (enumeration only)\n", encoding="utf-8"
            )

    def log(self, cmd, rc=0, duration_s=0.0, note=""):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = f"{ts}\trc={rc}\tdt={duration_s:.2f}s\t{cmd}"
        if note:
            line += f"\t# {note}"
        line += "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)


_FORCE_SVC_RE = re.compile(
    r"^(?:(?P<proto>tcp|udp)/)?(?P<port>\d{1,5})"
    r"(?:/(?P<service>[A-Za-z0-9._+-]+))?"
    r"(?:/(?P<version>.+))?$",
    re.I,
)


def parse_force_services(specs):
    """Parse force-services specs into (tcp_ports, udp_ports) dicts.

    Spec forms: 'tcp/80/http', '445/microsoft-ds', 'udp/53/domain',
    'tcp/443/https/nginx 1.18'. Pure; no network.
    """
    tcp, udp = {}, {}
    for raw in specs or []:
        s = (raw or "").strip()
        if not s:
            continue
        m = _FORCE_SVC_RE.match(s)
        if not m:
            raise ValueError(f"invalid force-services spec: {raw!r}")
        port = int(m.group("port"))
        if port < 1 or port > 65535:
            raise ValueError(f"port out of range in force-services: {raw!r}")
        proto = (m.group("proto") or "tcp").lower()
        service = (m.group("service") or "unknown").lower()
        version = (m.group("version") or "").strip()
        rec = _port_record(port, proto, service, version)
        if proto == "udp":
            udp[port] = rec
        else:
            tcp[port] = rec
    return tcp, udp


def parse_ports_spec(spec):
    """Parse --ports string into (tcp_list, udp_list).

    Examples: '80,443,445' | 'T:22,80,U:53,161' | '53,T:21-22,U:123'
    Pure; no network.
    """
    if not spec or not str(spec).strip():
        return [], []
    tcp, udp = [], []
    mode = "tcp"
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        upper = part.upper()
        if upper.startswith("T:"):
            mode = "tcp"
            part = part[2:]
        elif upper.startswith("U:"):
            mode = "udp"
            part = part[2:]
        elif upper.startswith("B:"):
            mode = "both"
            part = part[2:]
        if not part:
            continue
        if "-" in part and not part.startswith("-"):
            a, b = part.split("-", 1)
            if not (a.isdigit() and b.isdigit()):
                raise ValueError(f"invalid port range in --ports: {part!r}")
            lo, hi = int(a), int(b)
            if lo > hi or lo < 1 or hi > 65535:
                raise ValueError(f"invalid port range in --ports: {part!r}")
            ports = list(range(lo, hi + 1))
        else:
            if not part.isdigit():
                raise ValueError(f"invalid port in --ports: {part!r}")
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"port out of range in --ports: {part!r}")
            ports = [p]
        for p in ports:
            if mode in ("tcp", "both"):
                tcp.append(p)
            if mode in ("udp", "both"):
                udp.append(p)

    def _uniq(seq):
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return _uniq(tcp), _uniq(udp)


def seed_ports_from_known(force_specs=None, ports_spec=None):
    """Merge --force-services and --ports into (tcp_ports, udp_ports, skip_discovery)."""
    tcp, udp = {}, {}
    if force_specs:
        ft, fu = parse_force_services(force_specs)
        tcp.update(ft)
        udp.update(fu)
    if ports_spec:
        pt, pu = parse_ports_spec(ports_spec)
        for p in pt:
            tcp.setdefault(p, _port_record(p, "tcp", "unknown", ""))
        for p in pu:
            udp.setdefault(p, _port_record(p, "udp", "unknown", ""))
    skip = bool(tcp or udp)
    return tcp, udp, skip


def port_recon_subdir(recon_dir, port, proto="tcp"):
    """Return Path for per-port recon layout: recon/tcp80, recon/udp53."""
    d = Path(recon_dir) / f"{proto}{int(port)}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def select_service_type(port, service="", version="", proto="tcp"):
    """Map a port/service/version record to a recon dispatch key (pure).

    Uses module HTTP_PORTS / HTTPS_PORTS so obscure open ports still get
    HTTP probe when nmap labels them weirdly (e.g. krb524 on 4444).
    """
    port = int(port)
    svc = (service or "").lower()
    ver = (version or "").lower()

    # Dedicated non-HTTP surfaces first (often banner as http)
    if port == 23 or svc == "telnet" or "telnet" in svc:
        return "telnet"
    if port in (9200, 9300) or "elastic" in svc or "elasticsearch" in svc or "elasticsearch" in ver:
        return "elasticsearch"
    if port == 5601 or "kibana" in svc or "kibana" in ver:
        return "kibana"

    if port in (139, 445) or svc in ("microsoft-ds", "netbios-ssn", "smb") or svc == "smb":
        return "smb"
    if port == 53 or svc == "domain":
        return "dns"
    if port in (25, 465, 587) or svc == "smtp":
        return "smtp"
    if port in (161, 162) or svc == "snmp":
        return "snmp"
    if port in (389, 636, 3268, 3269) or svc == "ldap":
        return "ldap"
    # Alt-FTP (e.g. ccproxy-ftp on 2121) and classic :21
    if port == 21 or svc == "ftp" or "ftp" in svc:
        return "ftp"
    if port == 22 or svc == "ssh":
        return "ssh"
    if port == 3389 or svc in ("ms-wbt-server", "rdp"):
        return "rdp"
    if port == 3306 or svc == "mysql":
        return "mysql"
    if port == 1433 or svc in ("ms-sql-s", "mssql"):
        return "mssql"
    if port == 111 or svc == "rpcbind":
        return "rpc"
    if port == 2049 or svc == "nfs":
        return "nfs"
    if port in (5985, 5986) or svc == "wsman":
        return "winrm"
    if port == 88 or svc == "kerberos":
        return "kerberos"
    if port == 6379 or svc == "redis" or "redis" in svc:
        return "redis"
    if port in (5900, 5901, 5902) or svc == "vnc":
        return "vnc"
    if port == 69 or svc == "tftp":
        return "tftp"
    if port in (110, 143, 993, 995) or svc in ("pop3", "imap", "pop3s", "imaps"):
        return "mail"
    if port == 873 or svc == "rsync":
        return "rsync"
    if port == 11211 or svc in ("memcached", "memcache"):
        return "memcached"
    if port == 27017 or svc in ("mongodb", "mongod"):
        return "mongodb"
    if port == 5984 or svc == "couchdb":
        return "couchdb"
    if port == 5432 or svc == "postgresql":
        return "postgresql"

    svc_http_pattern = (
        "-http" in svc or "http-" in svc or svc.startswith(("ssl/", "https"))
        or svc in ("www", "wpl-analytics") or "api-daemon" in svc or "soap" in svc
    )
    http_ver = any(
        w in ver
        for w in (
            "apache", "nginx", "iis", "httpd", "tomcat", "lighttpd",
            "werkzeug", "gunicorn", "uwsgi", "kestrel", "node",
            "pve-api-daemon", "express",
        )
    )
    if svc in ("http", "https", "http-proxy", "ssl/http") or http_ver or svc_http_pattern:
        return "http"

    # Port-based HTTP fallback: full shared set (not a tiny subset)
    if port in HTTP_PORTS or port in HTTPS_PORTS:
        known_non_http = {
            "ssh", "ftp", "smtp", "domain", "smb", "microsoft-ds", "mysql",
            "ms-sql-s", "postgresql", "redis", "vnc", "telnet", "kerberos",
            "ms-wbt-server", "rpcbind", "nfs",
        }
        if svc in ("", "unknown", "tcpwrapped", "?", None) or not svc:
            return "http"
        if svc not in known_non_http:
            return "http"
    return None


def select_smb_enum_tool(available):
    """Prefer enum4linux-ng over classic enum4linux. available: set of tool names."""
    available = set(available or [])
    if "enum4linux-ng" in available:
        return "enum4linux-ng"
    if "enum4linux" in available:
        return "enum4linux"
    return None


def decide_vhost_actions(*, domain, tools_present=None, wordlist_exists=False, depth="normal"):
    """Virtual-host enum decision (enum only). Skip with explicit reason when missing deps."""
    actions = []
    if not domain:
        actions.append({
            "tool": "vhost_enum", "run": False,
            "reason": "no domain/hostname for vhost base", "weight": "heavy",
        })
        return actions
    if not wordlist_exists:
        actions.append({
            "tool": "vhost_enum", "run": False,
            "reason": f"vhost wordlist missing (base={domain})", "weight": "heavy",
        })
        return actions
    tool = None
    for cand in ("ffuf", "gobuster", "feroxbuster"):
        if tools_present is None or cand in tools_present:
            tool = cand
            break
    if tool is None:
        actions.append({
            "tool": "vhost_enum", "run": False,
            "reason": "no vhost tool (ffuf/gobuster/feroxbuster)", "weight": "heavy",
        })
        return actions
    actions.append({
        "tool": "vhost_enum", "run": True,
        "reason": f"vhost enum via {tool} base={domain} depth={depth}",
        "weight": "heavy",
        "via": tool,
    })
    return actions


def decide_subdomain_actions(*, domain, tools_present=None, wordlist_exists=False):
    """Subdomain enum decision (enum only)."""
    actions = []
    if not domain:
        actions.append({
            "tool": "subdomain_enum", "run": False,
            "reason": "no base domain for subdomain enum", "weight": "heavy",
        })
        return actions
    if not wordlist_exists:
        actions.append({
            "tool": "subdomain_enum", "run": False,
            "reason": f"subdomain wordlist missing (base={domain})", "weight": "heavy",
        })
        return actions
    tool = None
    for cand in ("gobuster", "ffuf", "dnsrecon"):
        if tools_present is None or cand in tools_present:
            tool = cand
            break
    if tool is None:
        actions.append({
            "tool": "subdomain_enum", "run": False,
            "reason": "no subdomain tool (gobuster/ffuf/dnsrecon)", "weight": "heavy",
        })
        return actions
    actions.append({
        "tool": "subdomain_enum", "run": True,
        "reason": f"subdomain enum via {tool} base={domain}",
        "weight": "heavy",
        "via": tool,
    })
    return actions


def run_multi_targets(targets, worker, *, max_workers=3, global_timeout_sec=None,
                      target_timeout_sec=None, clock=None):
    """Run worker(target) concurrently with global/per-target abandonment.

    Returns list of dicts:
      {target, status: ok|timeout|error|abandoned_global, result, error, duration_s}
    """
    targets = list(targets or [])
    max_workers = max(1, int(max_workers or 1))
    clock = clock or DeadlineClock(global_timeout_sec, target_timeout_sec)
    results = []
    if not targets:
        return results

    def _wrap(t):
        # Do not mutate shared clock.target_start (races under concurrent workers).
        # Workers own a per-thread DeadlineClock via set_deadline_clock / clone_for_target.
        t0 = time.monotonic()
        if clock.global_timeout_sec is not None and clock.expired():
            return {
                "target": t, "status": "abandoned_global",
                "result": None, "error": "global deadline expired before start",
                "duration_s": 0.0,
            }
        try:
            try:
                # Pass configured per-target budget (seconds); worker installs TLS clock
                res = worker(t, target_timeout_sec=clock.target_timeout_sec)
            except TypeError:
                res = worker(t)
            return {
                "target": t, "status": "ok", "result": res,
                "error": None, "duration_s": time.monotonic() - t0,
            }
        except TimeoutError as e:
            return {
                "target": t, "status": "timeout", "result": None,
                "error": str(e), "duration_s": time.monotonic() - t0,
            }
        except Exception as e:
            return {
                "target": t, "status": "error", "result": None,
                "error": str(e), "duration_s": time.monotonic() - t0,
            }

    if max_workers == 1 or len(targets) == 1:
        for t in targets:
            if clock.global_timeout_sec is not None and clock.expired():
                results.append({
                    "target": t, "status": "abandoned_global",
                    "result": None, "error": "global deadline expired",
                    "duration_s": 0.0,
                })
                continue
            results.append(_wrap(t))
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {}
        for t in targets:
            if clock.global_timeout_sec is not None and clock.expired():
                results.append({
                    "target": t, "status": "abandoned_global",
                    "result": None, "error": "global deadline expired before submit",
                    "duration_s": 0.0,
                })
                continue
            fut = pool.submit(_wrap, t)
            future_map[fut] = t

        pending = set(future_map.keys())
        while pending:
            wait_timeout = None
            if clock.global_timeout_sec is not None:
                rem = clock.remaining()
                if rem is not None and rem <= 0:
                    for fut in list(pending):
                        fut.cancel()
                        results.append({
                            "target": future_map[fut], "status": "abandoned_global",
                            "result": None, "error": "global deadline expired while waiting",
                            "duration_s": 0.0,
                        })
                    break
                wait_timeout = rem
            done, pending = concurrent_wait(pending, timeout=wait_timeout)
            for fut in done:
                try:
                    results.append(fut.result())
                except Exception as e:
                    results.append({
                        "target": future_map[fut], "status": "error",
                        "result": None, "error": str(e), "duration_s": 0.0,
                    })

    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r["target"], 9999))
    return results


def concurrent_wait(futures, timeout=None):
    """Thin wrapper around concurrent.futures.wait for testability."""
    from concurrent.futures import wait as _wait, FIRST_COMPLETED
    if not futures:
        return set(), set()
    if timeout is not None and timeout <= 0:
        return set(), set(futures)
    done, not_done = _wait(
        futures,
        timeout=None if timeout is None else max(0.01, float(timeout)),
        return_when=FIRST_COMPLETED,
    )
    return done, not_done


def _service_rank(rec):
    """Higher = richer service metadata (used when merging dual formats)."""
    svc = (rec.get("service") or "").lower()
    ver = rec.get("version") or ""
    rank = 0
    if svc and svc not in ("unknown", "?", "tcpwrapped"):
        rank += 2
    if svc == "tcpwrapped":
        rank += 1
    if ver and ver not in ("?",):
        rank += 2
    return rank


def merge_port_dicts(*dicts):
    """Merge port dicts; keep the richer service/version for each port."""
    out = {}
    for d in dicts:
        if not d:
            continue
        for port, rec in d.items():
            port = int(port)
            if port not in out or _service_rank(rec) > _service_rank(out[port]):
                out[port] = dict(rec)
                out[port]["port"] = port
    return out


def parse_nmap_xml_ports(nmap_file):
    """Parse nmap -oX XML for open ports and service/version fields."""
    import xml.etree.ElementTree as ET

    ports = {}
    path = Path(nmap_file)
    if not path.exists():
        return ports
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return ports
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue
        for port_el in host.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            try:
                port_id = int(port_el.get("portid"))
            except (TypeError, ValueError):
                continue
            proto = port_el.get("protocol") or "tcp"
            svc_el = port_el.find("service")
            service = ""
            version = ""
            if svc_el is not None:
                service = svc_el.get("name") or ""
                product = svc_el.get("product") or ""
                ver = svc_el.get("version") or ""
                extrainfo = svc_el.get("extrainfo") or ""
                # Mirror nmap -oN "product version (extrainfo)" style when present
                bits = [b for b in (product, ver) if b]
                version = " ".join(bits)
                if extrainfo:
                    version = f"{version} ({extrainfo})".strip() if version else extrainfo
            ports[port_id] = _port_record(port_id, proto, service, version)
    return ports


def parse_nmap_normal_ports(nmap_file):
    """Parse nmap -oN / greppable-style open port lines."""
    ports = {}
    path = Path(nmap_file)
    if not path.exists():
        return ports
    # 80/tcp  open  http  Apache httpd 2.4.41
    # 22/tcp open  ssh
    # Host: 10.0.0.1 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
    line_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+open(?:\|filtered)?\s+(\S+)\s*(.*)$",
        re.IGNORECASE,
    )
    grep_port_re = re.compile(
        r"(\d+)/(?:open|open\|filtered)/(tcp|udp)/([^/]*)/([^/]*)/([^/]*)/",
        re.IGNORECASE,
    )
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = line_re.match(line.strip())
            if m:
                port = int(m.group(1))
                ports[port] = _port_record(
                    port, m.group(2).lower(), m.group(3), m.group(4).strip()
                )
                continue
            if "Ports:" in line or "/open/" in line:
                for gm in grep_port_re.finditer(line):
                    port = int(gm.group(1))
                    proto = gm.group(2).lower()
                    # greppable: port/state/proto/owner/service/rpc/version/
                    service = (gm.group(4) or gm.group(3) or "").strip()
                    version = (gm.group(5) or "").strip()
                    ports[port] = _port_record(port, proto, service, version)
    return ports


def parse_nmap_ports(nmap_file):
    """Extract open ports and services from an nmap output file.

    Supports:
      - nmap -oN normal output
      - nmap -oG greppable fragments
      - nmap -oX XML (by extension or XML prolog)

    Enumeration only: reads scan artifacts; does not run exploits.
    """
    path = Path(nmap_file)
    if not path.exists():
        return {}
    # Prefer XML path when the file is clearly XML
    head = ""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(200)
    except OSError:
        return {}
    is_xml = path.suffix.lower() == ".xml" or head.lstrip().startswith("<?xml") or "<nmaprun" in head
    if is_xml:
        return parse_nmap_xml_ports(path)
    return parse_nmap_normal_ports(path)


def load_scan_ports(nmap_path):
    """Load ports from a scan artifact and merge sibling XML when present.

    Optimization over text-only parse: if ``quick.nmap`` has a sibling
    ``quick.xml`` (written by dual -oN/-oX), merge so service/version fields
    survive resume and incomplete rustscan stubs.
    """
    path = Path(nmap_path)
    ports = parse_nmap_ports(path) if path.exists() else {}
    # Sibling XML: quick.nmap -> quick.xml ; also accept .nmap.xml
    siblings = []
    if path.suffix.lower() == ".nmap":
        siblings.append(path.with_suffix(".xml"))
        siblings.append(Path(str(path) + ".xml"))
    elif path.suffix.lower() != ".xml":
        siblings.append(Path(str(path) + ".xml"))
    for sib in siblings:
        if sib.exists() and sib != path:
            ports = merge_port_dicts(ports, parse_nmap_ports(sib))
    return ports


def ports_csv(ports_dict):
    """Return comma-separated port list string."""
    return ",".join(str(p) for p in sorted(ports_dict.keys()))


def validate_target(target):
    """Return True if target is a safe IP, CIDR, or hostname (no shell metacharacters)."""
    valid = False
    try:
        ipaddress.ip_address(target)
        valid = True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        valid = True
    except ValueError:
        pass
    if not valid and re.match(r"^[a-zA-Z0-9._-]+$", target or ""):
        valid = True
    return valid

def guess_os_from_ttl(target):
    """Guess OS from ping TTL."""
    stdout, _, rc = run(f"ping -c 1 -W 2 {target} 2>/dev/null")
    if rc != 0:
        return "unknown", False
    m = re.search(r'ttl[=\s](\d+)', stdout, re.IGNORECASE)
    if not m:
        return "unknown", True
    ttl = int(m.group(1))
    if ttl <= 64:
        return "Linux/Unix", True
    elif ttl <= 128:
        return "Windows", True
    elif ttl <= 255:
        return "Network device", True
    return "unknown", True


# ── Scan Functions ──────────────────────────────────────────────────────

class Scanner:
    def __init__(self, target, outdir, rate=4, resume=False, fc=None):
        self.target = target
        self.outdir = Path(outdir)
        self.nmap_dir = self.outdir / "nmap"
        self.recon_dir = self.outdir / "recon"
        self.rate = rate
        self.resume = resume
        self.tcp_ports = {}   # port -> {port, proto, service, version}
        self.udp_ports = {}
        self.os_guess = "unknown"
        self.ping_flag = ""
        self.findings = []
        self.fc = fc  # optional FindingsCollector for shared JSONL output
        self.plugin_config = {}  # cantina.toml plugin config (set from main)
        self.plugin_registry = None  # cantina_plugins.PluginRegistry (set from main)
        # recon_depth: quick|normal|deep — gates heavy tool decisions
        self.recon_depth = "normal"
        self.decision_log = []  # list of decision records for audit / scorecard
        self.recon_errors = []  # isolated worker failures from concurrent recon
        self.recon_workers = 4  # concurrent independent service tasks
        self.skip_port_discovery = False  # True when --force-services/--ports seed map
        self.dirbust_tool = None  # feroxbuster|ffuf|gobuster override
        self.dirbust_wordlists = []  # optional list of wordlist paths
        self.dirbust_threads = None
        self.dirbust_ext = None  # comma-separated extensions without dots
        self.vhost_domain = None
        self.subdomain_domain = None
        self.vhost_wordlist = None
        self.subdomain_wordlist = None
        self._state_lock = threading.Lock()  # findings + decision_log + file append

        # Pick NSE script set: prefer custom 'jedi' if installed, else fall back to default,vuln.
        # Without this guard, --script jedi against a Kali without jedi.nse exits silently and
        # cantina interprets the empty result as "no open ports" — invisible failure mode.
        if nmap_script_available("jedi"):
            self.nse_scripts = "jedi"
        else:
            self.nse_scripts = "default,vuln"
            warn("jedi.nse not found in nmap script DB — falling back to '--script default,vuln'.")
            warn("Install: sudo cp /path/to/jedi.nse /usr/share/nmap/scripts/ && sudo nmap --script-updatedb")

        # Tunnel awareness: detect if target is behind a Hyperdrive pivot
        try:
            from tunnel import tunnel_ctx, tunnel_status_line
            self._tctx = tunnel_ctx(target)
            if self._tctx.tunneled:
                self.ping_flag = "-Pn"  # ICMP won't traverse tunnel
                info(f"Tunnel detected: {target} is behind {C.W}{self._tctx.interface}{C.RST} ({self._tctx.subnet})")
                info(f"Auto-applying: proxychains + -sT -Pn for all scans")
                tsl = tunnel_status_line()
                if tsl:
                    info(f"Hyperdrive: {tsl}")
        except ImportError:
            self._tctx = None

        # Manual commands collector (AutoRecon-style _manual_commands.txt)
        self._manual_cmds = []

        # Pattern matching results: list of (category, value, source)
        self._patterns = []
        self._pattern_regexes = {
            "username": [
                re.compile(r'(?:user(?:name)?|login|account)\s*[:=]\s*["\']?(\S+)', re.I),
                re.compile(r'User Name\s+:\s+(\S+)', re.I),
                re.compile(r'rid:\[0x[0-9a-f]+\]\s+(\S+)', re.I),
            ],
            "password": [
                re.compile(r'(?:pass(?:word)?|pwd|secret)\s*[:=]\s*["\']?(\S+)', re.I),
            ],
            "hash": [
                re.compile(r'([a-fA-F0-9]{32}:[a-fA-F0-9]{32})'),  # NTLM
                re.compile(r'\$(?:1|2[aby]?|5|6|y)\$[^\s:]+'),      # Unix crypt
                re.compile(r'([a-fA-F0-9]{32})(?:\s|$)'),            # MD5
            ],
            "email": [
                re.compile(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,})'),
            ],
            "version": [
                re.compile(r'(?:Server|X-Powered-By|Via):\s*(.+)', re.I),
                re.compile(r'(Apache|nginx|IIS|OpenSSH|vsftpd|ProFTPD|Samba|MySQL|PostgreSQL|Redis)\S*\s+(\d+\.\d+[\.\d]*)', re.I),
            ],
            "hostname": [
                re.compile(r'DNS_Computer_Name:\s*(\S+)', re.I),
                re.compile(r'DNS_Domain_Name:\s*(\S+)', re.I),
                re.compile(r'NetBIOS.*?name:\s*(\S+)', re.I),
            ],
            "private_key": [
                re.compile(r'(-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----)'),
            ],
        }

        # Create output dirs
        self.nmap_dir.mkdir(parents=True, exist_ok=True)
        self.recon_dir.mkdir(parents=True, exist_ok=True)
        (self.outdir / "exploit").mkdir(exist_ok=True)
        (self.outdir / "loot").mkdir(exist_ok=True)
        report_dir = self.outdir / "report"
        report_dir.mkdir(exist_ok=True)
        # Create report templates if they don't exist
        for fname, content in [
            ("local.txt", ""),
            ("proof.txt", ""),
            ("notes.txt", f"# Notes for {target}\n\n## Credentials\n\n## Flags\n\n## Attack Chain\n\n"),
        ]:
            p = report_dir / fname
            if not p.exists():
                p.write_text(content)

    def add_finding(self, severity, category, message, exploit_cmd=""):
        rec = {
            "severity": severity,
            "category": category,
            "message": message,
            "exploit_cmd": exploit_cmd,
        }
        lock = getattr(self, "_state_lock", None)
        if lock:
            with lock:
                self.findings.append(rec)
        else:
            self.findings.append(rec)
        ui.finding(severity, category, message, exploit_cmd=exploit_cmd)
        if self.fc:
            self.fc.add(severity, category, message, exploit_cmd=exploit_cmd)

    def parse_jedi_findings(self, nmap_output_path):
        """Scan nmap script output for jedi-style [SEVERITY] tags and add as findings.

        jedi.nse emits structured tags inside its script output blocks:
            | jedi: [INFO] Banner: SSH-2.0-OpenSSH_10.0
            | [LOW] Missing X-Frame-Options header
            |_[CRITICAL] Anonymous SMB share writable

        Without this parser the tags get logged into nmap output but never
        bubble up to the findings counter — so a CRITICAL finding from jedi
        was previously invisible in the summary. INFO tags are skipped to
        avoid double-counting (port-level INFO is added by the scan loops).
        """
        try:
            text = Path(nmap_output_path).read_text(errors='replace')
        except Exception:
            return
        port_re = re.compile(r'^(\d+/(?:tcp|udp))\s+open\s+(\S+)')
        sev_re = re.compile(r'^[|\s_]*(?:jedi:\s*)?\[(INFO|LOW|WARNING|HIGH|CRITICAL)\]\s+(.+?)\s*$')
        current_port = None
        seen = set()
        for line in text.splitlines():
            m = port_re.match(line)
            if m:
                current_port = m.group(1)
                continue
            m = sev_re.match(line)
            if not m:
                continue
            sev = m.group(1)
            msg = m.group(2).strip()
            if sev == "INFO":
                continue  # port-level INFO already added by quick_scan/full_scan
            key = (sev, msg, current_port)
            if key in seen:
                continue
            seen.add(key)
            cat = f"jedi:{current_port}" if current_port else "jedi"
            self.add_finding(sev, cat, msg)

    def _should_skip(self, output_file):
        """Check if scan should be skipped (resume mode)."""
        if not self.resume:
            return False
        path = self.nmap_dir / output_file if "/" not in output_file else Path(output_file)
        if path.exists() and path.stat().st_size > 100:
            info(f"Resume: skipping, output exists: {C.W}{path.name}")
            return True
        return False

    def _wrap(self, cmd: str) -> str:
        """Wrap command with proxychains if target is behind a tunnel."""
        if self._tctx and self._tctx.tunneled:
            return self._tctx.wrap(cmd)
        return cmd

    def _nmap(self, args, output_name, timeout=600):
        """Run nmap with standard flags and save output. Tunnel-aware.

        Always dual-writes -oN (human) and -oX (structured). XML siblings let
        resume/merge keep service+version when normal text is sparse.
        """
        ofile = self.nmap_dir / output_name
        # Force -sT through tunnel (SYN scan won't work through SOCKS)
        scan_type_override = ""
        if self._tctx and self._tctx.tunneled and "-sU" not in args and "-sT" not in args:
            scan_type_override = "-sT"
        # Pair .nmap text with .xml for the same stem (quick.nmap + quick.xml)
        stem = ofile.stem if ofile.suffix.lower() == ".nmap" else ofile.name
        xfile = self.nmap_dir / f"{stem}.xml"
        cmd = (
            f"nmap {self.ping_flag} {scan_type_override} -T{self.rate} "
            f"--max-retries 2 --max-scan-delay 20 {args} "
            f"-oN {ofile} -oX {xfile} {self.target}"
        )
        cmd = self._wrap(cmd.replace("  ", " "))
        info(f"Running: {C.D}{cmd}")
        stdout, rc = run_live(cmd, timeout=timeout)
        self.extract_patterns(stdout, source=f"nmap:{output_name}")
        return ofile, rc

    def _rustscan_discover(self):
        """Try rustscan for fast port discovery. Returns set of open ports, or None if unavailable."""
        # Skip if tunneled (rustscan doesn't support proxychains well)
        if self._tctx and self._tctx.tunneled:
            dimm("Skipping rustscan (tunneled target, using nmap -p- instead)")
            return None

        if not tool_exists("rustscan"):
            return None

        info(f"Using {C.W}rustscan{C.C} for fast port discovery (nmap will handle service detection)")
        cmd = f"rustscan -a {self.target} --ulimit 5000 -t 2000 -b 1000 -- -oN /dev/null"
        # rustscan outputs "Open {ip}:{port}" lines
        stdout, stderr, rc = run(cmd, timeout=120)

        if rc != 0:
            warn(f"rustscan failed (rc={rc}), falling back to nmap")
            return None

        ports = set()
        for line in (stdout + "\n" + stderr).splitlines():
            # Match "Open <ip>:<port>" or just port numbers in the output
            m = re.search(r'Open\s+\S+:(\d+)', line)
            if m:
                ports.add(int(m.group(1)))
            # Also match the summary line: "PORT   STATE SERVICE"
            m2 = re.match(r'^(\d+)/tcp\s+open', line)
            if m2:
                ports.add(int(m2.group(1)))

        if not ports:
            # Try parsing the greppable format rustscan sometimes uses
            for line in stdout.splitlines():
                # "Ports: 22,80,443,8080"
                m = re.search(r'(?:Ports?:?\s*)([\d,\s]+)', line)
                if m:
                    for p in m.group(1).split(","):
                        p = p.strip()
                        if p.isdigit():
                            ports.add(int(p))

        if ports:
            good(f"rustscan found {C.W}{len(ports)}{C.G} open ports in seconds")
            for p in sorted(ports):
                dimm(f"  {p}/tcp open")
            return ports
        else:
            warn("rustscan returned no ports, falling back to nmap")
            return None

    # ── Network Sweep ──────────────────────────────────────────────────

    def network_sweep(self, cidr):
        """Sweep a subnet for live hosts."""
        section("NETWORK SWEEP")

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            warn(f"Invalid CIDR: {e}")
            return []

        info(f"Sweeping {C.W}{network}{C.C} ({network.num_addresses} addresses)")

        ofile = self.nmap_dir / f"network_{str(network.network_address).replace('.', '_')}.nmap"
        cmd = f"nmap -T{self.rate} -sn -n -oN {ofile} {cidr}"
        info(f"Running: {C.D}{cmd}")
        stdout, rc = run_live(cmd, timeout=120)

        # Parse live hosts
        hosts = []
        with open(ofile) as f:
            for line in f:
                m = re.search(r'Nmap scan report for (\S+)', line)
                if m:
                    hosts.append(m.group(1))

        if hosts:
            subsection(f"Live Hosts ({len(hosts)})")
            for h in hosts:
                good(f"{C.W}{h}")
                vader_log_host(h, source="cantina")
            # Save host list
            hostfile = self.outdir / "live_hosts.txt"
            with open(hostfile, "w") as f:
                f.write("\n".join(hosts))
            good(f"Saved to {C.W}{hostfile}")
        else:
            warn("No live hosts found")

        return hosts

    # ── Quick Scan ─────────────────────────────────────────────────────

    def quick_scan(self):
        """Top 1000 TCP ports + service/version detection."""
        section("QUICK SCAN (Top Ports + Scripts)")

        if self._should_skip("quick.nmap"):
            self.tcp_ports.update(load_scan_ports(self.nmap_dir / "quick.nmap"))
            return

        ofile, rc = self._nmap(f"--open -sCV --script {self.nse_scripts}", "quick.nmap", timeout=300)
        new_ports = load_scan_ports(ofile)
        self.tcp_ports.update(new_ports)

        if new_ports:
            subsection(f"Open Ports ({len(new_ports)})")
            for p in sorted(new_ports.values(), key=lambda x: x["port"]):
                svc = f"{p['service']}" + (f" {p['version']}" if p['version'] else "")
                good(f"{C.W}{p['port']}/{p['proto']}{C.RST}  {svc}")
                self.add_finding("INFO", "Port", f"{p['port']}/{p['proto']} {svc}")
            vader_log_host(self.target, ports=[p["port"] for p in new_ports.values()], source="cantina")
        else:
            warn("No open ports found in top 1000")

        # Promote jedi script tags ([LOW]/[WARNING]/[HIGH]/[CRITICAL]) to findings
        self.parse_jedi_findings(ofile)

    # ── Full Scan ──────────────────────────────────────────────────────

    def full_scan(self):
        """All 65535 TCP ports, then scripts on newly discovered ports."""
        section("FULL PORT SCAN (All 65535 TCP)")

        if self._should_skip("full.nmap"):
            full_ports = load_scan_ports(self.nmap_dir / "full.nmap")
            self.tcp_ports.update(full_ports)
            return

        # Phase 1: fast port discovery
        # Try rustscan first (3-10 seconds for all 65535 ports), fall back to nmap
        rustscan_ports = self._rustscan_discover()
        if rustscan_ports is not None:
            # Rustscan found ports, write a minimal nmap-format file for consistency
            ofile = self.nmap_dir / "full.nmap"
            with open(ofile, "w") as f:
                f.write(f"# Nmap-compatible output from rustscan discovery\n")
                f.write(f"# Ports discovered by rustscan, service detection pending\n")
                for port in sorted(rustscan_ports):
                    f.write(f"{port}/tcp  open  unknown\n")
            full_ports = {p: _port_record(p, "tcp", "unknown", "") for p in rustscan_ports}
        else:
            # Rustscan not available or failed, use nmap -p-
            ofile, rc = self._nmap("-p- --open --min-rate 1000", "full.nmap", timeout=900)
            full_ports = load_scan_ports(ofile)

        # Find new ports not in quick scan
        known = set(self.tcp_ports.keys())
        new_ports = {p: v for p, v in full_ports.items() if p not in known}

        if new_ports:
            subsection(f"New Ports Found ({len(new_ports)})")
            for p in sorted(new_ports.values(), key=lambda x: x["port"]):
                warn(f"New: {C.W}{p['port']}/{p['proto']}{C.RST}  {p['service']}")

            # Phase 2: run scripts on new ports only
            new_csv = ",".join(str(p) for p in sorted(new_ports.keys()))
            info(f"Running scripts + jedi on new ports: {C.W}{new_csv}")
            ofile2, rc2 = self._nmap(f"-p {new_csv} -sCV --script {self.nse_scripts}", "full_extra.nmap", timeout=300)
            extra_ports = load_scan_ports(ofile2)
            # Merge detailed info (prefer richer service/version)
            new_ports = merge_port_dicts(new_ports, extra_ports)
            # Promote jedi script tags from the script-pass output too
            self.parse_jedi_findings(ofile2)
        else:
            good("No new ports beyond quick scan")

        self.tcp_ports = merge_port_dicts(self.tcp_ports, full_ports, new_ports if new_ports else {})

    # ── UDP Scan ───────────────────────────────────────────────────────

    def udp_scan(self):
        """Top 200 UDP ports."""
        section("UDP SCAN (Top 200)")

        if not is_root():
            warn("UDP scan requires root. Skipping.")
            warn(f"Re-run with: {C.C}sudo python3 cantina.py {self.target} -t udp")
            return

        if self._should_skip("udp.nmap"):
            self.udp_ports.update(load_scan_ports(self.nmap_dir / "udp.nmap"))
            return

        ofile, rc = self._nmap("-sU --top-ports 200 --open --max-retries 1", "udp.nmap", timeout=600)
        self.udp_ports = load_scan_ports(ofile)

        if self.udp_ports:
            subsection(f"Open UDP Ports ({len(self.udp_ports)})")
            for p in sorted(self.udp_ports.values(), key=lambda x: x["port"]):
                svc = f"{p['service']}" + (f" {p['version']}" if p['version'] else "")
                good(f"{C.W}{p['port']}/udp{C.RST}  {svc}")
                self.add_finding("INFO", "UDP", f"{p['port']}/udp {svc}")
        else:
            good("No open UDP ports in top 200")

    # ── Vuln Scan ──────────────────────────────────────────────────────

    def vuln_scan(self):
        """CVE + vuln scripts on discovered TCP ports."""
        section("VULNERABILITY SCAN")

        if not self.tcp_ports:
            warn("No TCP ports discovered yet, skipping vuln scan")
            return

        port_list = ports_csv(self.tcp_ports)

        if self._should_skip("vulns.nmap"):
            return

        # CVE scan with vulners
        subsection("CVE Detection (vulners)")
        ofile, rc = self._nmap(
            f"-p {port_list} --script vulners --script-args mincvss=7.0",
            "vulns_cve.nmap", timeout=600
        )
        # Parse CVEs from output
        if ofile.exists():
            with open(ofile) as f:
                for line in f:
                    if "CVE-" in line:
                        m = re.search(r'(CVE-\d{4}-\d+)', line)
                        if m:
                            cve = m.group(1)
                            score_m = re.search(r'(\d+\.\d+)', line)
                            score = score_m.group(1) if score_m else "?"
                            crit(f"{C.W}{cve}{C.RST} (CVSS: {score})")
                            self.add_finding("CRITICAL", "CVE", f"{cve} (CVSS {score})",
                                             f"searchsploit {cve}")

        # Vuln scripts
        subsection("Nmap Vuln Scripts")
        ofile2, rc2 = self._nmap(
            f"-p {port_list} --script vuln",
            "vulns_scripts.nmap", timeout=600
        )
        if ofile2.exists():
            with open(ofile2) as f:
                for line in f:
                    if "VULNERABLE" in line:
                        warn(f"Vuln: {C.W}{line.strip()}")
                        self.add_finding("CRITICAL", "Vuln", line.strip())

    # ── Searchsploit ──────────────────────────────────────────────────

    def searchsploit_scan(self):
        """Query searchsploit for every discovered service version."""
        section("SEARCHSPLOIT (Exploit-DB Lookup)")

        if not tool_exists("searchsploit"):
            warn("searchsploit not found (install: sudo apt install exploitdb)")
            return

        all_ports = {**self.tcp_ports, **self.udp_ports}
        if not all_ports:
            warn("No services discovered, skipping searchsploit")
            return

        # Build unique search terms from service versions
        # "Apache httpd 2.4.49" -> search "Apache 2.4.49"
        # "OpenSSH 7.2p2 Ubuntu" -> search "OpenSSH 7.2"
        queries_done = set()

        for port_info in sorted(all_ports.values(), key=lambda x: x["port"]):
            version = port_info["version"]
            service = port_info["service"]
            port = port_info["port"]

            if not version or version in ("?", ""):
                continue

            # Extract the product name + version number
            search_terms = self._build_searchsploit_queries(service, version)

            for term in search_terms:
                if term in queries_done:
                    continue
                queries_done.add(term)

                subsection(f"searchsploit: {term} (port {port})")
                # --json for structured output, --no-colour for clean parsing
                raw, stderr, rc = run(
                    f"searchsploit --no-colour '{term}' 2>/dev/null",
                    timeout=15
                )

                if not raw or "No Results" in raw or rc != 0:
                    good(f"No exploits found for {term}")
                    continue

                # Parse searchsploit output
                exploit_count = 0
                ofile = self.recon_dir / f"searchsploit_{term.replace(' ', '_').replace('/', '_')}.txt"
                with open(ofile, "w") as f:
                    f.write(raw)

                for line in raw.splitlines():
                    line = line.strip()
                    # Skip header/footer lines
                    if not line or line.startswith("-") or line.startswith("Exploit Title") or "Shellcodes:" in line or "Papers:" in line:
                        continue

                    # Prioritize RCE, LFI, auth bypass, privesc
                    lower = line.lower()
                    is_critical = any(kw in lower for kw in [
                        "remote code", "rce", "command injection", "command execution",
                        "file inclusion", "lfi", "rfi", "path traversal",
                        "authentication bypass", "auth bypass",
                        "privilege escalation", "privesc",
                        "arbitrary file", "sql injection",
                        "buffer overflow", "bof",
                    ])
                    is_dos = "denial of service" in lower or "dos" in lower

                    if is_dos:
                        # Skip DoS exploits (not useful for OSCP)
                        continue
                    elif is_critical:
                        crit(f"{C.W}{line}")
                        exploit_count += 1
                        self.add_finding("CRITICAL", "Exploit-DB",
                                         f"{term}: {line.split('|')[0].strip() if '|' in line else line}",
                                         f"searchsploit -m {line.split('|')[-1].strip() if '|' in line else ''}")
                    else:
                        warn(f"{line}")
                        exploit_count += 1

                if exploit_count > 0:
                    info(f"Copy exploit: {C.C}searchsploit -m EXPLOIT_PATH{C.RST}")
                    info(f"Full results saved to {C.D}{ofile}{C.RST}")

    @staticmethod
    def _build_searchsploit_queries(service, version):
        """Build searchsploit query terms from nmap service/version strings.

        nmap outputs versions like:
            "Apache httpd 2.4.49"
            "OpenSSH 7.2p2 Ubuntu 4ubuntu2.10"
            "Microsoft IIS httpd 10.0"
            "ProFTPD 1.3.5"
            "vsftpd 2.3.4"
            "nginx 1.18.0"
            "Samba smbd 4.6.2"

        We want search terms like:
            "Apache 2.4.49", "Apache httpd 2.4"
            "OpenSSH 7.2", "OpenSSH 7.2p2"
        """
        queries = []
        version = version.strip()
        if not version:
            return queries

        # Extract the first version number
        ver_match = re.search(r'(\d+\.\d+[\.\d]*[a-z]*\d*)', version)
        if not ver_match:
            # No version number found, search the whole string
            queries.append(version.split("(")[0].strip()[:40])
            return queries

        ver_num = ver_match.group(1)
        # Get the product name (everything before the version number)
        product = version[:ver_match.start()].strip()

        # Clean up common nmap suffixes
        product = product.replace("httpd", "").strip()
        product = re.sub(r'\s+', ' ', product).strip()

        if not product:
            # Fallback to service name
            product = service

        # Primary: "Product X.Y.Z"
        queries.append(f"{product} {ver_num}")

        # Secondary: "Product X.Y" (catches broader matches)
        major_minor = re.match(r'(\d+\.\d+)', ver_num)
        if major_minor and major_minor.group(1) != ver_num:
            queries.append(f"{product} {major_minor.group(1)}")

        return queries

    # ── Service Recon ──────────────────────────────────────────────────

    # Class aliases → module frozensets (single source of truth)
    HTTP_PORTS = HTTP_PORTS  # noqa: F811 — bind module HTTP_PORTS on class
    HTTPS_PORTS = HTTPS_PORTS

    def _log_decision(self, svc_type, port, actions, extra=None, duration_ms=None):
        """Record decision branch outcomes (enum audit trail). Thread-safe."""
        rec = {
            "svc": svc_type,
            "port": port,
            "depth": getattr(self, "recon_depth", "normal"),
            "actions": actions or [],
            "ran": [a["tool"] for a in (actions or []) if a.get("run")],
            "skipped": [
                f"{a['tool']}: {a.get('reason', '')}"
                for a in (actions or []) if not a.get("run")
            ],
        }
        if duration_ms is not None:
            rec["duration_ms"] = round(float(duration_ms), 3)
        if extra:
            rec["extra"] = extra
        path = self.recon_dir / "decision_log.jsonl"
        lock = getattr(self, "_state_lock", None)

        def _write():
            self.decision_log.append(rec)
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            except Exception:
                pass

        if lock:
            with lock:
                _write()
        else:
            _write()
        # Console: show branch summary
        ran = rec["ran"]
        skipped_n = len(rec["skipped"])
        info(
            f"Decision [{svc_type}:{port}] depth={rec['depth']} "
            f"run={ran or '[]'} skip={skipped_n}"
            + (f" {rec.get('duration_ms', 0):.0f}ms" if rec.get("duration_ms") is not None else "")
        )
        for a in actions or []:
            mark = "RUN " if a.get("run") else "SKIP"
            dimm(f"  {mark} {a.get('tool')}: {a.get('reason', '')}")

    def apply_known_ports(self, force_specs=None, ports_spec=None):
        """Seed tcp/udp port maps from --force-services / --ports; skip rediscovery."""
        tcp, udp, skip = seed_ports_from_known(force_specs, ports_spec)
        if tcp:
            self.tcp_ports = merge_port_dicts(self.tcp_ports, tcp)
        if udp:
            self.udp_ports = merge_port_dicts(self.udp_ports, udp)
        self.skip_port_discovery = bool(skip)
        return skip

    def port_dir(self, port, proto="tcp"):
        """Per-port recon artifact directory under recon/."""
        return port_recon_subdir(self.recon_dir, port, proto)

    def build_recon_tasks(self):
        """Build independent (svc_type, port, extra) tasks from discovered ports.

        Uses select_service_type() for dispatch keys (incl. telnet/ES/kibana).
        Pure-ish: no I/O, no tool runs. Safe to call offline for bench/tests.
        """
        all_ports = {**self.tcp_ports, **self.udp_ports}
        if not all_ports:
            return []

        dispatched = set()
        tasks = []

        # Skip built-in tasks for services owned by replaces_builtin plugins
        replaced = set()
        try:
            from cantina_plugins import replaced_builtin_services
            replaced = replaced_builtin_services(getattr(self, "plugin_registry", None))
        except ImportError:
            replaced = set()

        for port, info_dict in sorted(all_ports.items()):
            svc = (info_dict.get("service") or "").lower()
            ver = (info_dict.get("version") or "").lower()
            proto = (info_dict.get("proto") or "tcp").lower()
            svc_type = select_service_type(port, svc, ver, proto)
            if not svc_type:
                continue
            if svc_type in replaced:
                continue  # plugin owns this service path

            # Dedup keys: one http task per port; most other services once
            if svc_type == "http":
                key = f"http_{port}"
            elif svc_type == "mail":
                key = "mail"
            else:
                key = svc_type
            if key in dispatched:
                continue
            dispatched.add(key)

            if svc_type == "http":
                scheme = "https" if (
                    port in self.HTTPS_PORTS or "ssl" in svc or "https" in svc
                ) else "http"
                tasks.append(("http", port, scheme))
            elif svc_type == "mail":
                tasks.append(("mail", port, svc or "mail"))
            else:
                tasks.append((svc_type, port, None))

        return tasks

    def service_recon(self):
        """Dispatch service-specific tools based on discovered ports.

        Independent services run concurrently (ThreadPoolExecutor).
        Within each service: probe → decide → conditional tools (serial).
        Worker failures are isolated; siblings continue. Enum only.
        After built-ins: run matching custom plugins (additive).
        """
        section("SERVICE-SPECIFIC RECON")
        info(f"Recon depth: {C.W}{getattr(self, 'recon_depth', 'normal')}")

        tasks = self.build_recon_tasks()
        if not tasks:
            warn("No recognizable services to dispatch recon for")
            # Still allow custom plugins on seeded/discovered ports
            try:
                self.run_service_plugins()
            except Exception as e:
                warn(f"Plugin phase error: {e}")
            return

        workers = max(1, int(getattr(self, "recon_workers", 4) or 4))
        info(
            f"Dispatching recon for {C.W}{len(tasks)}{C.C} service types "
            f"(workers={workers})"
        )
        results = self.run_recon_concurrent(tasks, max_workers=workers)
        errs = [r for r in results if not r.get("ok")]
        if errs:
            warn(f"{len(errs)} service recon worker(s) failed (isolated)")
            for r in errs:
                t = r.get("task")
                dimm(f"  fail {t}: {r.get('error')}")

        # Additive custom plugin phase (enum only)
        try:
            pret = self.run_service_plugins()
            if pret:
                n_ok = sum(1 for r in pret if r.get("ok"))
                info(f"Custom plugins: {C.W}{n_ok}/{len(pret)}{C.C} ok")
        except Exception as e:
            warn(f"Plugin phase error: {e}")

    def run_service_plugins(self):
        """Run matching enabled plugins for all known ports (enum only).

        Independent plugin×port jobs run concurrently (same isolation as
        built-in recon workers). Safe with empty registry.
        """
        reg = getattr(self, "plugin_registry", None)
        if reg is None or len(reg) == 0:
            return []

        try:
            from cantina_plugins import (
                build_context_from_scanner,
                plan_plugin_jobs,
                run_plugin,
            )
        except ImportError:
            warn("cantina_plugins module not available")
            return []

        section("CUSTOM PLUGINS")
        info(f"Registry: {C.W}{len(reg)}{C.C} plugin(s) loaded")
        all_ports = {**self.tcp_ports, **self.udp_ports}
        if not all_ports:
            dimm("No ports for plugin matching")
            return []

        jobs = plan_plugin_jobs(all_ports, reg, select_service_type)
        if not jobs:
            dimm("No plugins matched open ports")
            return []

        workers = max(1, int(getattr(self, "recon_workers", 4) or 4))
        info(f"Plugin jobs: {C.W}{len(jobs)}{C.C} (workers={workers})")

        # Cap per-plugin wall time by recon depth (speed without killing deep enum)
        depth = (getattr(self, "recon_depth", "normal") or "normal").lower()
        default_timeout = {"quick": 45, "normal": 120, "deep": 300}.get(depth, 120)

        def _run_cmd(cmd, timeout=None):
            t = default_timeout if timeout is None else min(int(timeout), default_timeout * 2)
            return run(self._wrap(cmd) if hasattr(self, "_wrap") else cmd, timeout=t)

        def worker(job):
            plug = job["plugin"]
            port = int(job["port"])
            proto = job["proto"]
            info(f"Plugin {C.W}{plug.name}{C.C} on {port}/{proto} ({job.get('svc_type') or job.get('service') or '?'})")
            ctx = build_context_from_scanner(
                self,
                port,
                proto=proto,
                service=job.get("service") or "",
                version=job.get("version") or "",
                svc_type=job.get("svc_type") or "",
                run_cmd=_run_cmd,
                extra={
                    "ping_flag": getattr(self, "ping_flag", "") or "",
                    "recon_depth": depth,
                    "default_timeout": default_timeout,
                },
            )
            one = run_plugin(plug, ctx)
            try:
                self._log_decision(
                    f"plugin:{plug.name}",
                    port,
                    [{
                        "tool": plug.name,
                        "run": bool(one.get("ok") and not one.get("skipped")),
                        "reason": one.get("reason") or one.get("error") or "plugin run",
                        "weight": "light",
                    }],
                    extra={"plugin": one},
                )
            except Exception:
                pass
            return one

        isolated = run_tasks_isolated(jobs, worker, max_workers=workers, inherit_tls=True)
        results = []
        for r in isolated:
            if r.get("ok") and r.get("result") is not None:
                one = r["result"]
                results.append(one)
                if one.get("ok") and one.get("artifact"):
                    dimm(f"  artifact: {one['artifact']}")
                elif one.get("skipped"):
                    dimm(f"  skipped: {one.get('reason')}")
                elif not one.get("ok"):
                    warn(f"  plugin error: {one.get('error')}")
            else:
                warn(f"  plugin worker fail: {r.get('error')}")
                results.append({
                    "ok": False,
                    "error": r.get("error"),
                    "plugin": (r.get("task") or {}).get("plugin_name"),
                })

        if not results:
            dimm("No plugins matched open ports")
        return results

    def run_recon_concurrent(self, tasks, max_workers=4):
        """Run independent recon tasks concurrently with isolated errors.

        Returns list of result dicts from run_tasks_isolated.
        """
        self.recon_errors = []

        def worker(task):
            svc_type, port, extra = task
            t0 = time.perf_counter()
            self._recon_dispatch(svc_type, port, extra)
            ms = (time.perf_counter() - t0) * 1000.0
            # Attach duration onto last matching decision if present
            lock = getattr(self, "_state_lock", None)

            def _stamp():
                for rec in reversed(self.decision_log):
                    if rec.get("svc") == svc_type and rec.get("port") == port:
                        rec.setdefault("duration_ms", round(ms, 3))
                        break

            if lock:
                with lock:
                    _stamp()
            else:
                _stamp()
            return {"svc": svc_type, "port": port, "duration_ms": round(ms, 3)}

        results = run_tasks_isolated(tasks, worker, max_workers=max_workers)
        for r in results:
            if not r.get("ok"):
                err_rec = {
                    "task": list(r.get("task") or ()),
                    "error": r.get("error"),
                    "duration_ms": r.get("duration_ms"),
                }
                self.recon_errors.append(err_rec)
                # Decision-shaped record so tool-use score still sees the service
                try:
                    t = r.get("task") or ("?", 0, None)
                    self._log_decision(
                        t[0] if len(t) > 0 else "?",
                        t[1] if len(t) > 1 else 0,
                        [{
                            "tool": "worker",
                            "run": False,
                            "reason": f"isolated error: {r.get('error')}",
                            "weight": "light",
                        }],
                        extra={"worker_error": r.get("error")},
                        duration_ms=r.get("duration_ms"),
                    )
                except Exception:
                    pass
        return results

    def _find_tool(self, name):
        """Find a custom toolkit tool by name. Checks ~/tools/, ~/, and PATH."""
        for base in [Path.home() / "tools", Path.home(), Path(".")]:
            p = base / name
            if p.exists():
                return str(p)
        return None

    def _run_custom_tool(self, tool_name, args, label, timeout=120):
        """Run a custom toolkit tool if available."""
        tool_path = self._find_tool(tool_name)
        if not tool_path:
            return False
        info(f"{C.G}[TOOLKIT]{C.RST} Running {C.W}{label}{C.RST}...")
        cmd = f"python3 {tool_path} {args}"
        cmd_hint(cmd)
        stdout, stderr, rc = run(cmd, timeout=timeout)
        if stdout:
            self.extract_patterns(stdout, source=tool_name)
            # Print last 20 lines (summary section)
            lines = stdout.strip().splitlines()
            summary_start = len(lines)
            for i, line in enumerate(lines):
                if "SUMMARY" in line or "ATTACK PATHS" in line:
                    summary_start = max(0, i - 1)
                    break
            for line in lines[summary_start:]:
                out(f"    {line}")
        return rc == 0

    def _recon_run(self, cmd, timeout=300):
        """Run a recon command, wrapping with proxychains if tunneled. Auto-extracts patterns."""
        stdout, stderr, rc = run(self._wrap(cmd), timeout=timeout)
        self.extract_patterns(stdout, source=cmd.split()[0] if cmd else "recon")
        return stdout, stderr, rc

    def _run_plugin_commands(self, svc_type, port, url=None):
        """Run custom commands from cantina.toml for this service type."""
        if not self.plugin_config:
            return
        svc_conf = self.plugin_config.get(svc_type, {})
        commands = svc_conf.get("commands", [])
        if not commands:
            return
        subsection(f"Plugin Commands ({svc_type})")
        for cmd_template in commands:
            cmd = cmd_template.format(
                target=self.target,
                port=port,
                url=url or f"http://{self.target}:{port}",
                outdir=self.recon_dir,
            )
            info(f"Plugin: {C.D}{cmd}")
            cmd_hint(cmd)
            stdout, stderr, rc = run(self._wrap(cmd), timeout=300)
            self.extract_patterns(stdout, source=f"plugin:{svc_type}")
            if stdout:
                ofile = self.recon_dir / f"plugin_{svc_type}_{port}.txt"
                with open(ofile, "w") as f:
                    f.write(stdout)
                for line in stdout.strip().splitlines()[-10:]:
                    info(f"  {line}")
            if rc != 0 and stderr:
                dimm(f"  Plugin error: {stderr[:200]}")

    def _recon_dispatch(self, svc_type, port, extra):
        """Dispatch recon for a specific service type.

        Services owned by replaces_builtin plugins are skipped here; the
        custom plugin phase runs their enum logic instead (no double-run).
        """
        target = self.target
        try:
            from cantina_plugins import replaced_builtin_services
            replaced = replaced_builtin_services(getattr(self, "plugin_registry", None))
        except ImportError:
            replaced = set()
        if svc_type and svc_type in replaced:
            dimm(f"Built-in {svc_type} skipped — owned by plugin (replaces_builtin)")
            return

        if svc_type == "http":
            scheme = extra
            url = f"{scheme}://{target}:{port}"
            subsection(f"HTTP Recon ({url})")

            # ── Branch 0: cheap probe → signals → decide_http_actions ──
            hdr_out, _, _ = run(
                f"curl -skI --max-time 5 -A 'cantina-enum' {url} 2>/dev/null",
                timeout=10,
            )
            body_out, _, _ = run(
                f"curl -sk --max-time 5 -A 'cantina-enum' {url} 2>/dev/null | head -c 2048",
                timeout=10,
            )
            signals = parse_http_probe(hdr_out, body_out)
            # Enrich CMS from whatweb later; seed from nmap version if present
            port_rec = self.tcp_ports.get(port) or self.udp_ports.get(port) or {}
            ver_blob = f"{port_rec.get('service','')} {port_rec.get('version','')}".lower()
            if not signals.get("cms"):
                if "wordpress" in ver_blob:
                    signals["cms"] = "wordpress"
                elif "juice" in ver_blob:
                    signals["cms"] = "juice-shop"

            present = {"http_probe"}  # probe always "available" (curl path)
            for t in ("whatweb", "feroxbuster", "ffuf", "gobuster", "nikto", "wpscan", "sslscan"):
                if tool_exists(t):
                    present.add(t)
            if any(x in present for x in ("feroxbuster", "ffuf", "gobuster")):
                present.add("dirbust")
            if self._find_tool("jarjar.py"):
                present.add("jarjar")

            actions = decide_http_actions(
                signals,
                depth=getattr(self, "recon_depth", "normal"),
                port=port,
                tools_present=present,
            )
            # sslscan only for https
            if scheme == "https" and "sslscan" in present:
                actions.append({
                    "tool": "sslscan", "run": True,
                    "reason": "HTTPS scheme — SSL/TLS enum", "weight": "light",
                })
            else:
                actions.append({
                    "tool": "sslscan", "run": False,
                    "reason": "not https or sslscan missing", "weight": "light",
                })

            self._log_decision("http", port, actions, extra={"url": url, "signals": signals})
            want = {a["tool"] for a in actions_to_run(actions)}

            # Persist probe
            probe_file = self.recon_dir / f"http_probe_{port}.txt"
            with open(probe_file, "w", encoding="utf-8") as f:
                f.write(f"URL: {url}\nSIGNALS: {json.dumps(signals)}\n\n--- headers ---\n{hdr_out}\n\n--- body ---\n{body_out}\n")

            if not signals.get("looks_http"):
                warn(f"Port {port}: open but not HTTP — skip web tools")
                return

            # ── Branch: light fingerprint ──
            if "whatweb" in want and tool_exists("whatweb"):
                ofile = self.recon_dir / f"whatweb_{port}.txt"
                stdout, _, _ = run(f"whatweb {url} --color=never 2>/dev/null", timeout=30)
                if stdout:
                    with open(ofile, "w") as f:
                        f.write(stdout)
                    for line in stdout.splitlines():
                        if line.strip():
                            info(f"  {line.strip()}")
                    lower = stdout.lower()
                    if "wordpress" in lower and signals.get("cms") != "wordpress":
                        signals["cms"] = "wordpress"
                        warn(f"WordPress detected on port {port}")
                    elif "joomla" in lower:
                        warn(f"Joomla detected on port {port}")
                        cmd_hint(f"joomscan -u {url}")
                    elif "drupal" in lower:
                        warn(f"Drupal detected on port {port}")
                        cmd_hint(f"droopescan scan drupal -u {url}")

            if "jarjar" in want:
                self._run_custom_tool(
                    "jarjar.py",
                    f"{url} -o {self.recon_dir}/jarjar_{port}.txt --quiet",
                    f"Jar Jar HTTP scan on port {port}",
                    timeout=120,
                )

            # ── Branch: heavy dirbust (conditional; CLI overrides) ──
            pdir = port_recon_subdir(self.recon_dir, port, "tcp")
            if "dirbust" in want:
                common_wl = "/usr/share/wordlists/dirb/common.txt"
                medium_wl = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
                depth = getattr(self, "recon_depth", "normal")
                high = port in _HTTP_HIGH_VALUE
                custom_wls = list(getattr(self, "dirbust_wordlists", None) or [])
                if custom_wls:
                    wordlists = [w for w in custom_wls if os.path.exists(w)]
                    if not wordlists:
                        wordlists = custom_wls[:1]  # still try first path
                else:
                    if (depth == "deep" or high) and os.path.exists(medium_wl):
                        wordlists = [medium_wl]
                    elif os.path.exists(common_wl):
                        wordlists = [common_wl]
                    else:
                        wordlists = [medium_wl if os.path.exists(medium_wl) else common_wl]
                wl = wordlists[0]
                thr = getattr(self, "dirbust_threads", None) or 40
                ext = getattr(self, "dirbust_ext", None)
                prefer = (getattr(self, "dirbust_tool", None) or "").lower() or None

                def _has(name):
                    return tool_exists(name)

                order = ["feroxbuster", "ffuf", "gobuster"]
                if prefer in order:
                    order = [prefer] + [x for x in order if x != prefer]
                chosen = next((t for t in order if _has(t)), None)

                if chosen == "feroxbuster":
                    ofile = pdir / f"feroxbuster_{port}.txt"
                    ext_flag = f" -x {ext}" if ext else ""
                    cmd = (
                        f"feroxbuster -u {url} -w {wl} -t {thr} -o {ofile} "
                        f"--no-state -q{ext_flag} 2>/dev/null"
                    )
                    info(f"Feroxbuster: {C.D}{url} ({Path(wl).name})")
                    cmd_hint(cmd)
                    run(cmd, timeout=300)
                    self.add_finding("INFO", "Web", f"Dirbust completed on {url}")
                elif chosen == "ffuf":
                    ofile = pdir / f"ffuf_{port}.txt"
                    ext_flag = f" -e {','.join('.' + e for e in ext.split(','))}" if ext else ""
                    cmd = (
                        f"ffuf -u {url}/FUZZ -w {wl} -t {thr} -mc all -fc 404 "
                        f"-o {ofile} -of csv{ext_flag} 2>/dev/null"
                    )
                    info(f"FFUF: {C.D}{url}")
                    cmd_hint(cmd)
                    run(cmd, timeout=300)
                elif chosen == "gobuster":
                    ofile = pdir / f"gobuster_{port}.txt"
                    ext_flag = f" -x {ext}" if ext else ""
                    cmd = (
                        f"gobuster dir -u {url} -w {wl} -t {thr} -o {ofile}"
                        f"{ext_flag} 2>/dev/null"
                    )
                    info(f"Gobuster: {C.D}{url}")
                    cmd_hint(cmd)
                    run(cmd, timeout=300)
                else:
                    warn("No web fuzzer found (feroxbuster/ffuf/gobuster)")
            else:
                dimm(f"Dirbust skipped on {port} (decision branch)")

            # ── Branch: virtual host + subdomain enum (first-class) ──
            vhost_domain = getattr(self, "vhost_domain", None)
            if not vhost_domain:
                # try Host header / target hostname
                if any(c.isalpha() for c in str(self.target)):
                    vhost_domain = self.target
            vhost_wl = getattr(self, "vhost_wordlist", None) or (
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
                if os.path.exists("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
                else "/usr/share/seclists/Discovery/Web-Content/common.txt"
            )
            vhost_tools = {t for t in ("ffuf", "gobuster", "feroxbuster") if tool_exists(t)}
            v_actions = decide_vhost_actions(
                domain=vhost_domain,
                tools_present=vhost_tools or None,
                wordlist_exists=bool(vhost_wl and os.path.exists(vhost_wl)),
                depth=getattr(self, "recon_depth", "normal"),
            )
            self._log_decision("http_vhost", port, v_actions, extra={"domain": vhost_domain})
            if actions_to_run(v_actions):
                via = next((a.get("via") for a in v_actions if a.get("run")), "ffuf")
                ofile = pdir / f"vhost_{port}.txt"
                info(f"Vhost enum ({via}) base={vhost_domain}")
                if via == "ffuf" and tool_exists("ffuf"):
                    cmd = (
                        f"ffuf -u {url} -H 'Host: FUZZ.{vhost_domain}' "
                        f"-w {vhost_wl} -mc all -fc 404 -o {ofile} -of csv 2>/dev/null"
                    )
                elif via == "gobuster" and tool_exists("gobuster"):
                    cmd = (
                        f"gobuster vhost -u {url} -w {vhost_wl} "
                        f"--domain {vhost_domain} -o {ofile} 2>/dev/null"
                    )
                else:
                    cmd = (
                        f"ffuf -u {url} -H 'Host: FUZZ.{vhost_domain}' "
                        f"-w {vhost_wl} -mc all -o {ofile} -of csv 2>/dev/null"
                    )
                cmd_hint(cmd)
                run(cmd, timeout=300)
            else:
                reason = v_actions[0]["reason"] if v_actions else "skipped"
                dimm(f"Vhost enum skipped: {reason}")

            sub_domain = getattr(self, "subdomain_domain", None) or vhost_domain
            sub_wl = getattr(self, "subdomain_wordlist", None) or vhost_wl
            sub_tools = {t for t in ("gobuster", "ffuf", "dnsrecon") if tool_exists(t)}
            s_actions = decide_subdomain_actions(
                domain=sub_domain,
                tools_present=sub_tools or None,
                wordlist_exists=bool(sub_wl and os.path.exists(sub_wl)),
            )
            self._log_decision("http_subdomain", port, s_actions, extra={"domain": sub_domain})
            if actions_to_run(s_actions):
                via = next((a.get("via") for a in s_actions if a.get("run")), "gobuster")
                ofile = pdir / f"subdomain_{port}.txt"
                info(f"Subdomain enum ({via}) base={sub_domain}")
                if via == "dnsrecon" and tool_exists("dnsrecon"):
                    cmd = f"dnsrecon -d {sub_domain} -t brt -D {sub_wl} 2>/dev/null | tee {ofile}"
                elif via == "ffuf" and tool_exists("ffuf"):
                    cmd = (
                        f"ffuf -u http://FUZZ.{sub_domain}/ -w {sub_wl} "
                        f"-mc 200,301,302,403 -o {ofile} -of csv 2>/dev/null"
                    )
                else:
                    cmd = (
                        f"gobuster dns -d {sub_domain} -w {sub_wl} "
                        f"-o {ofile} 2>/dev/null"
                    )
                cmd_hint(cmd)
                run(cmd, timeout=300)
            else:
                reason = s_actions[0]["reason"] if s_actions else "skipped"
                dimm(f"Subdomain enum skipped: {reason}")

            # ── Branch: nikto (conditional) ──
            if "nikto" in want and tool_exists("nikto"):
                ofile = self.recon_dir / f"nikto_{port}.txt"
                cmd = f"nikto -h {url} -o {ofile} -Format txt -maxtime 120s 2>/dev/null"
                info(f"Nikto: {C.D}{url}")
                cmd_hint(cmd)
                run(cmd, timeout=180)
            elif "nikto" not in want:
                dimm(f"Nikto skipped on {port} (decision branch)")

            # ── Branch: CMS tools ──
            if "wpscan" in want and tool_exists("wpscan"):
                wp_ofile = self.recon_dir / f"wpscan_{port}.txt"
                cmd = f"wpscan --url {url} -e vp,vt,u --no-banner -o {wp_ofile} 2>/dev/null"
                info(f"WPScan: {C.D}{url}")
                cmd_hint(cmd)
                run(cmd, timeout=300)
                self.add_finding("WARNING", "Web", f"WordPress on port {port}", cmd)

            if "sslscan" in want and tool_exists("sslscan"):
                ofile = self.recon_dir / f"sslscan_{port}.txt"
                stdout, _, _ = run(f"sslscan --no-colour {target}:{port} 2>/dev/null", timeout=30)
                if stdout:
                    with open(ofile, "w") as f:
                        f.write(stdout)
                    if "SSLv3" in stdout or "TLSv1.0" in stdout:
                        warn(f"Legacy SSL/TLS on port {port}")

            self._run_plugin_commands("http", port, url=url)

        elif svc_type == "smb":
            subsection("SMB Recon")

            # ── Branch 0: null-session probe ──
            null_list_ok = False
            shares_readable = False
            access_denied = False
            smb_stdout = ""
            if tool_exists("smbclient"):
                ofile = self.recon_dir / "smbclient_null.txt"
                smb_stdout, _, _ = run(f"smbclient -L //{target} -N 2>/dev/null", timeout=15)
                if smb_stdout:
                    with open(ofile, "w") as f:
                        f.write(smb_stdout)
                    for line in smb_stdout.splitlines():
                        if "Disk" in line or "IPC" in line:
                            info(f"  {line.strip()}")
                    access_denied = "NT_STATUS_ACCESS_DENIED" in smb_stdout
                    null_list_ok = (not access_denied) and (
                        "Disk" in smb_stdout or "Sharename" in smb_stdout or "IPC" in smb_stdout
                    )
                    if null_list_ok:
                        warn("Null session SMB listing succeeded")
                        self.add_finding(
                            "WARNING", "SMB", "Null session SMB listing allowed",
                            f"smbclient -L //{target} -N",
                        )

            actions = decide_smb_actions(
                null_list_ok=null_list_ok,
                shares_readable=shares_readable,
                access_denied=access_denied,
            )
            self._log_decision("smb", port, actions, extra={
                "null_list_ok": null_list_ok,
                "access_denied": access_denied,
            })
            want = {a["tool"] for a in actions_to_run(actions)}

            if "jawa" in want:
                self._run_custom_tool(
                    "jawa.py",
                    f"{target} -o {self.recon_dir}",
                    "Jawa SMB enumeration",
                    timeout=180,
                )

            if "smbmap" in want and tool_exists("smbmap"):
                ofile = self.recon_dir / "smbmap_null.txt"
                stdout, _, _ = run(f"smbmap -H {target} --no-banner 2>/dev/null", timeout=15)
                if stdout:
                    with open(ofile, "w") as f:
                        f.write(stdout)
                    for line in stdout.splitlines():
                        if "READ" in line or "WRITE" in line:
                            warn(f"  {line.strip()}")
                            shares_readable = True

            if "enum4linux" in want:
                avail = set()
                if tool_exists("enum4linux-ng"):
                    avail.add("enum4linux-ng")
                if tool_exists("enum4linux"):
                    avail.add("enum4linux")
                enum_tool = select_smb_enum_tool(avail)
                if enum_tool:
                    ofile = self.recon_dir / f"{enum_tool.replace('-', '_')}.txt"
                    info(f"{enum_tool}: {C.D}{target}")
                    if enum_tool == "enum4linux-ng":
                        cmd = f"enum4linux-ng -A {target} 2>/dev/null"
                    else:
                        cmd = f"enum4linux -a {target} 2>/dev/null"
                    cmd_hint(cmd)
                    stdout, _, _ = run(cmd, timeout=120)
                    if stdout:
                        with open(ofile, "w") as f:
                            f.write(stdout)
                else:
                    dimm("enum4linux(-ng) not installed")
            else:
                dimm("enum4linux skipped (null denied / decision branch)")

            if "nmap_smb_scripts" in want:
                ofile = self.recon_dir / "nmap_smb.txt"
                # Safe detection scripts only. No ms08-067 (can crash legacy boxes).
                smb_scripts = ",".join([
                    "smb-enum-shares", "smb-enum-users", "smb-os-discovery",
                    "smb-vuln-ms17-010",
                    "smb-vuln-cve-2020-0796",
                    "smb-protocols",
                    "smb-security-mode",
                ])
                run(
                    f"nmap {self.ping_flag} -p 139,445 --script '{smb_scripts}' "
                    f"-oN {ofile} {target} 2>/dev/null",
                    timeout=120,
                )
                if ofile.exists():
                    with open(ofile) as f:
                        content = f.read()
                    if "VULNERABLE" in content:
                        crit("SMB vulnerability detected (EternalBlue?)")
                        self.add_finding(
                            "CRITICAL", "SMB", "SMB vulnerability detected",
                            f"Check {ofile}",
                        )

        elif svc_type == "dns":
            subsection("DNS Recon")

            # Custom toolkit: Maul
            # Try to get domain from hostname or target
            domain = target
            if not any(c.isalpha() for c in target):
                # IP address, try reverse lookup for domain
                import socket as _socket
                try:
                    domain = _socket.gethostbyaddr(target)[0]
                except Exception:
                    domain = target
            self._run_custom_tool("maul.py",
                f"{domain} -ns {target} -o {self.recon_dir}",
                f"Maul DNS enumeration ({domain})", timeout=300)

            if tool_exists("dnsrecon"):
                ofile = self.recon_dir / "dnsrecon.txt"
                stdout, _, _ = run(f"dnsrecon -d {target} -t axfr 2>/dev/null", timeout=30)
                if stdout:
                    with open(ofile, "w") as f:
                        f.write(stdout)
                    if "Zone Transfer" in stdout and "unsuccessful" not in stdout.lower():
                        crit("DNS zone transfer successful!")
                        self.add_finding("CRITICAL", "DNS", "Zone transfer allowed",
                                         f"dnsrecon -d {target} -t axfr")

            if tool_exists("dig"):
                stdout, _, _ = run(f"dig axfr @{target} 2>/dev/null", timeout=15)
                if stdout and "AXFR" in stdout and "Transfer failed" not in stdout:
                    crit("DNS zone transfer via dig")
                    ofile = self.recon_dir / "dig_axfr.txt"
                    with open(ofile, "w") as f:
                        f.write(stdout)

        elif svc_type == "smtp":
            subsection(f"SMTP Recon (port {port})")
            if tool_exists("smtp-user-enum"):
                ofile = self.recon_dir / "smtp_users.txt"
                wordlist = "/usr/share/wordlists/metasploit/unix_users.txt"
                if os.path.exists(wordlist):
                    cmd = f"smtp-user-enum -M VRFY -U {wordlist} -t {target} -p {port} 2>/dev/null"
                    info(f"SMTP user enum: {C.D}{target}:{port}")
                    cmd_hint(cmd)
                    stdout, _, _ = run(cmd, timeout=120)
                    if stdout:
                        with open(ofile, "w") as f:
                            f.write(stdout)
            # nmap smtp scripts
            run(f"nmap {self.ping_flag} -p {port} --script 'smtp-enum-users,smtp-commands,smtp-open-relay' -oN {self.recon_dir}/nmap_smtp.txt {target} 2>/dev/null", timeout=60)

        elif svc_type == "snmp":
            # Owned by plugins/snmp_enum.py when replaces_builtin is active.
            # Fallback only if plugin registry failed to load that plugin.
            subsection("SNMP Recon (built-in fallback)")
            warn(
                "Built-in SNMP path hit — prefer plugins/snmp_enum.py "
                "(replaces_builtin). Install/load plugins or fix --plugins-dir."
            )
            cmd_hint(f"snmpwalk -v2c -c public {target}")
            cmd_hint(f"onesixtyone {target}")
            self.add_finding("INFO", "SNMP", f"SNMP port {port} (plugin preferred for full enum)")

        elif svc_type == "ldap":
            subsection(f"LDAP Recon (port {port})")

            # Suggest Ackbar (needs creds + domain, can't auto-run without them)
            info(f"{C.G}[TOOLKIT]{C.RST} LDAP detected. After getting creds, run Ackbar:")
            cmd_hint(f"python3 ~/tools/ackbar.py -d DOMAIN -u USER -p PASS -dc {target} --report findings.md")

            if tool_exists("ldapsearch"):
                ofile = self.recon_dir / "ldap_anonymous.txt"
                stdout, _, _ = run(
                    f"ldapsearch -x -H ldap://{target}:{port} -b '' -s base namingContexts 2>/dev/null",
                    timeout=15
                )
                if stdout and "namingContexts" in stdout:
                    with open(ofile, "w") as f:
                        f.write(stdout)
                    info(f"LDAP base DN found")
                    # Try anonymous bind for full dump
                    m = re.search(r'namingContexts:\s*(.+)', stdout)
                    if m:
                        base_dn = m.group(1).strip()
                        info(f"  Base DN: {C.W}{base_dn}")
                        anon_out, _, _ = run(
                            f"ldapsearch -x -H ldap://{target}:{port} -b '{base_dn}' '(objectClass=*)' 2>/dev/null | head -100",
                            timeout=30
                        )
                        if anon_out and "numEntries" not in anon_out:
                            dimm("Anonymous bind returned no entries")
                        elif anon_out:
                            warn("Anonymous LDAP bind returns data!")
                            self.add_finding("WARNING", "LDAP", "Anonymous LDAP bind allowed",
                                             f"ldapsearch -x -H ldap://{target}:{port} -b '{base_dn}'")

        elif svc_type == "ftp":
            # Owned by plugins/ftp_enum.py when replaces_builtin is active.
            subsection("FTP Recon (built-in fallback)")
            warn(
                "Built-in FTP path hit — prefer plugins/ftp_enum.py "
                "(replaces_builtin). Install/load plugins or fix --plugins-dir."
            )
            cmd_hint(f"nmap -p {port} --script ftp-anon,ftp-syst {target}")
            cmd_hint(f"ftp {target} {port}")
            self.add_finding("INFO", "FTP", f"FTP port {port} (plugin preferred for full enum)")

        elif svc_type == "ssh":
            subsection(f"SSH Recon (port {port})")
            ofile = self.recon_dir / "nmap_ssh.txt"
            run(f"nmap {self.ping_flag} -p {port} --script 'ssh-auth-methods,ssh2-enum-algos' -oN {ofile} {target} 2>/dev/null", timeout=30)
            if ofile.exists():
                with open(ofile) as f:
                    content = f.read()
                    if "password" in content:
                        info("SSH accepts password authentication")
                    if "publickey" in content:
                        info("SSH accepts publickey authentication")

        elif svc_type == "rdp":
            subsection(f"RDP Recon (port {port})")
            ofile = self.recon_dir / "nmap_rdp.txt"
            run(f"nmap {self.ping_flag} -p {port} --script 'rdp-enum-encryption,rdp-ntlm-info,rdp-vuln-ms12-020' -oN {ofile} {target} 2>/dev/null", timeout=60)
            if ofile.exists():
                with open(ofile) as f:
                    content = f.read()
                    if "VULNERABLE" in content:
                        crit("RDP vulnerability (MS12-020 / BlueKeep?)")
                        self.add_finding("CRITICAL", "RDP", "RDP vulnerability detected")
                    # NTLM info leak
                    m = re.search(r'DNS_Computer_Name:\s*(\S+)', content)
                    if m:
                        info(f"  Hostname: {C.W}{m.group(1)}")
                    m = re.search(r'DNS_Domain_Name:\s*(\S+)', content)
                    if m:
                        info(f"  Domain: {C.W}{m.group(1)}")
                        self.add_finding("INFO", "RDP", f"Domain: {m.group(1)}")

        elif svc_type == "mysql":
            subsection(f"MySQL Recon (port {port})")

            # Custom toolkit: Boba Fett
            self._run_custom_tool("bobafett.py",
                f"{target} -p {port} --type mysql -o {self.recon_dir}",
                f"Boba Fett MySQL enumeration on port {port}", timeout=60)

            ofile = self.recon_dir / "nmap_mysql.txt"
            run(f"nmap {self.ping_flag} -p {port} --script 'mysql-info,mysql-enum,mysql-empty-password,mysql-vuln-cve2012-2122' -oN {ofile} {target} 2>/dev/null", timeout=60)
            if ofile.exists():
                with open(ofile) as f:
                    content = f.read()
                    if "empty-password" in content.lower() and "VULNERABLE" in content:
                        crit("MySQL allows empty password!")
                        self.add_finding("CRITICAL", "MySQL", "Empty password allowed")

        elif svc_type == "mssql":
            subsection(f"MSSQL Recon (port {port})")

            # Custom toolkit: Boba Fett
            self._run_custom_tool("bobafett.py",
                f"{target} -p {port} --type mssql -o {self.recon_dir}",
                f"Boba Fett MSSQL enumeration on port {port}", timeout=60)

            ofile = self.recon_dir / "nmap_mssql.txt"
            run(f"nmap {self.ping_flag} -p {port} --script 'ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info' -oN {ofile} {target} 2>/dev/null", timeout=60)

        elif svc_type == "rpc":
            subsection("RPC Recon")
            if tool_exists("rpcinfo"):
                ofile = self.recon_dir / "rpcinfo.txt"
                stdout, _, _ = run(f"rpcinfo -p {target} 2>/dev/null", timeout=15)
                if stdout:
                    with open(ofile, "w") as f:
                        f.write(stdout)
                    for line in stdout.splitlines()[:15]:
                        info(f"  {line}")

                    # Flag NFS if visible in RPC
                    if "nfs" in stdout.lower():
                        warn("NFS registered in RPC. Check NFS exports:")
                        cmd_hint(f"showmount -e {target}")

            # nmap RPC scripts
            ofile = self.recon_dir / "nmap_rpc.txt"
            run(f"nmap {self.ping_flag} -p 111 --script 'rpcinfo,nfs-showmount' -oN {ofile} {target} 2>/dev/null", timeout=30)

        elif svc_type == "nfs":
            subsection("NFS Recon")

            # Phase 1: nmap NFS scripts
            ofile = self.recon_dir / "nmap_nfs.txt"
            run(f"nmap {self.ping_flag} -p 111,2049 --script 'nfs-ls,nfs-showmount,nfs-statfs' -oN {ofile} {target} 2>/dev/null", timeout=60)
            if ofile.exists():
                with open(ofile) as f:
                    content = f.read()
                    if "showmount" in content.lower() or "/" in content:
                        warn("NFS exports found via nmap!")

            # Phase 2: showmount enumeration
            exports = []
            if tool_exists("showmount"):
                stdout, _, _ = run(f"showmount -e {target} 2>/dev/null", timeout=15)
                if stdout and "Export list" in stdout:
                    for line in stdout.splitlines():
                        info(f"  {line}")
                    # Parse export paths and access masks
                    for m in re.finditer(r'^(/\S+)\s+(.+)$', stdout, re.MULTILINE):
                        export_path = m.group(1)
                        access = m.group(2).strip()
                        exports.append((export_path, access))
                        if access == "*" or access == "(everyone)":
                            crit(f"NFS share {export_path} accessible to EVERYONE!")
                            self.add_finding("CRITICAL", "NFS", f"World-accessible NFS export: {export_path}",
                                             f"mount -t nfs {target}:{export_path} /mnt/nfs")
                        else:
                            self.add_finding("WARNING", "NFS", f"NFS export: {export_path} ({access})",
                                             f"mount -t nfs {target}:{export_path} /mnt/nfs")

                    ofile_exp = self.recon_dir / "nfs_exports.txt"
                    with open(ofile_exp, "w") as f:
                        f.write(stdout)

            # Phase 3: try mounting each export and listing contents
            if exports:
                info("  Attempting to mount and list exports...")
                for export_path, access in exports:
                    safe_name = export_path.replace("/", "_").strip("_") or "root"
                    mnt_point = f"/tmp/nfs_cantina_{safe_name}"
                    run(f"mkdir -p {mnt_point} 2>/dev/null", timeout=5)
                    _, _, rc = run(f"mount -t nfs -o nolock,vers=3 {target}:{export_path} {mnt_point} 2>/dev/null", timeout=15)
                    if rc != 0:
                        # Try NFSv4
                        _, _, rc = run(f"mount -t nfs4 {target}:{export_path} {mnt_point} 2>/dev/null", timeout=15)

                    if rc == 0:
                        warn(f"  Mounted {export_path} successfully!")
                        # List first level
                        stdout, _, _ = run(f"ls -la {mnt_point}/ 2>/dev/null", timeout=10)
                        if stdout:
                            ofile_ls = self.recon_dir / f"nfs_listing_{safe_name}.txt"
                            with open(ofile_ls, "w") as f:
                                f.write(f"=== {export_path} ===\n{stdout}\n")
                            for line in stdout.splitlines()[:20]:
                                info(f"    {line}")

                            # Check for interesting files
                            stdout_find, _, _ = run(
                                f"find {mnt_point} -maxdepth 3 \\( -name '*.conf' -o -name '*.cfg' -o -name '*.bak' "
                                f"-o -name '*.key' -o -name '*.pem' -o -name 'id_rsa*' -o -name '*.kdbx' "
                                f"-o -name 'shadow' -o -name 'passwd' -o -name '.bash_history' "
                                f"-o -name 'wp-config.php' -o -name 'web.config' -o -name '*.sql' \\) "
                                f"-type f 2>/dev/null",
                                timeout=15
                            )
                            if stdout_find:
                                crit(f"  Interesting files in {export_path}:")
                                for fline in stdout_find.strip().splitlines()[:10]:
                                    warn(f"    {fline}")
                                self.add_finding("CRITICAL", "NFS",
                                    f"Sensitive files on NFS {export_path}: {stdout_find.strip().splitlines()[0]}",
                                    f"mount -t nfs {target}:{export_path} /mnt/nfs && find /mnt/nfs -name '*.conf' -o -name 'id_rsa*'")

                            # Check for no_root_squash (can we write as root?)
                            _, _, rc_touch = run(f"touch {mnt_point}/.nfs_write_test 2>/dev/null", timeout=5)
                            if rc_touch == 0:
                                run(f"rm -f {mnt_point}/.nfs_write_test 2>/dev/null", timeout=5)
                                warn(f"  {export_path} is WRITABLE (possible no_root_squash)")
                                self.add_finding("CRITICAL", "NFS",
                                    f"Writable NFS export (no_root_squash?): {export_path}",
                                    f"# PrivEsc: copy bash with SUID to {export_path}\n"
                                    f"cp /bin/bash {mnt_point}/bash_suid && chmod +s {mnt_point}/bash_suid")

                        # Unmount
                        run(f"umount {mnt_point} 2>/dev/null", timeout=10)
                    run(f"rmdir {mnt_point} 2>/dev/null", timeout=5)

            # Phase 4: rpcinfo for NFS-related services
            if tool_exists("rpcinfo"):
                stdout, _, _ = run(f"rpcinfo -p {target} 2>/dev/null | grep -i nfs", timeout=10)
                if stdout:
                    info("  NFS RPC services:")
                    for line in stdout.splitlines()[:10]:
                        info(f"    {line}")

        elif svc_type == "winrm":
            subsection(f"WinRM (port {port})")
            info("WinRM detected. If you have creds:")
            cmd_hint(f"evil-winrm -i {target} -u USER -p PASS")
            cmd_hint(f"evil-winrm -i {target} -u USER -H HASH")
            self.add_finding("INFO", "WinRM", f"WinRM open on port {port}")

        elif svc_type == "kerberos":
            subsection("Kerberos (port 88)")
            info("Kerberos detected. This is likely a Domain Controller.")

            # Try to extract domain from LDAP or nmap output
            domain = None
            for p, pinfo in self.tcp_ports.items():
                if "Domain:" in pinfo.get("version", ""):
                    m = re.search(r'Domain:\s*([a-zA-Z0-9.-]+)', pinfo["version"])
                    if m:
                        domain = m.group(1)
                        break
            if domain:
                info(f"  Domain: {C.W}{domain}")

            # Kerbrute user enumeration (no creds needed)
            # WHY: Kerberos pre-auth lets us validate usernames without credentials.
            # Valid usernames are needed for password spraying, AS-REP roasting, and targeted attacks.
            if tool_exists("kerbrute") and domain:
                userlist = None
                for wl in ["/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt",
                           "/usr/share/seclists/Usernames/Names/names.txt",
                           "/usr/share/wordlists/metasploit/unix_users.txt"]:
                    if os.path.exists(wl):
                        userlist = wl
                        break
                if userlist:
                    ofile = self.recon_dir / "kerbrute_users.txt"
                    info(f"Enumerating valid domain users via Kerberos (no creds needed)...")
                    cmd = f"kerbrute userenum -d {domain} --dc {target} {userlist} -o {ofile} 2>/dev/null"
                    cmd_hint(cmd)
                    stdout, _, rc = run(cmd, timeout=120)
                    if stdout:
                        valid_users = re.findall(r'VALID USERNAME:\s+(\S+)', stdout)
                        if valid_users:
                            crit(f"Valid users found via Kerberos: {', '.join(valid_users[:15])}")
                            self.add_finding("CRITICAL", "Kerberos",
                                f"Valid domain users: {', '.join(valid_users[:15])}",
                                f"kerbrute userenum -d {domain} --dc {target} {userlist}")

            # AS-REP roast (no creds needed, checks for accounts without pre-auth)
            # WHY: Accounts with "Do not require Kerberos pre-authentication" can have their
            # password hash requested and cracked offline. Common OSCP foothold.
            if tool_exists("impacket-GetNPUsers") and domain:
                ofile = self.recon_dir / "asrep_roast.txt"
                info(f"Checking for AS-REP roastable accounts (no creds needed)...")
                # If we found users from kerbrute, use those
                kerb_users_file = self.recon_dir / "kerbrute_users.txt"
                if kerb_users_file.exists():
                    cmd = f"impacket-GetNPUsers {domain}/ -dc-ip {target} -usersfile {kerb_users_file} -format hashcat -outputfile {ofile} 2>/dev/null"
                else:
                    cmd = f"impacket-GetNPUsers {domain}/ -dc-ip {target} -request -format hashcat -outputfile {ofile} 2>/dev/null"
                cmd_hint(cmd)
                stdout, _, _ = run(cmd, timeout=60)
                if ofile.exists() and ofile.stat().st_size > 0:
                    crit(f"AS-REP roastable accounts found!")
                    self.add_finding("CRITICAL", "Kerberos", "AS-REP roastable accounts",
                                     f"hashcat -m 18200 {ofile} /usr/share/wordlists/rockyou.txt")

            self.add_finding("WARNING", "Kerberos", f"Domain Controller detected (port 88){f' - {domain}' if domain else ''}",
                             f"python3 ~/tools/ackbar.py -d {domain or 'DOMAIN'} -u USER -p PASS -dc {target}")

        # ── Redis ──────────────────────────────────────────────────
        elif svc_type == "redis":
            subsection(f"Redis (port {port})")
            info("Redis detected. Probe unauth access (no brute)...")

            pong = False
            if tool_exists("redis-cli"):
                pout, _, _ = run(
                    f"redis-cli -h {target} -p {port} --raw PING 2>/dev/null",
                    timeout=8,
                )
                pong = (pout or "").strip().upper() == "PONG"
            else:
                # Fallback: nmap redis-info only (never redis-brute)
                ofile = self.recon_dir / f"redis_{port}_nmap.txt"
                nmap_cmd = (
                    f"nmap -sV -p {port} --script redis-info "
                    f"-oN {ofile} {target} 2>/dev/null"
                )
                cmd_hint(self._wrap(nmap_cmd))
                stdout, _, _ = run(self._wrap(nmap_cmd), timeout=60)
                pong = "redis_version" in (stdout or "").lower()

            actions = decide_redis_actions(pong=pong)
            self._log_decision("redis", port, actions, extra={"pong": pong})
            want = {a["tool"] for a in actions_to_run(actions)}

            if "nmap_redis_info" in want:
                ofile = self.recon_dir / f"redis_{port}_nmap.txt"
                if not ofile.exists():
                    nmap_cmd = (
                        f"nmap -sV -p {port} --script redis-info "
                        f"-oN {ofile} {target} 2>/dev/null"
                    )
                    run(self._wrap(nmap_cmd), timeout=60)

            if "redis_info" in want and tool_exists("redis-cli"):
                info_out, _, _ = run(
                    f"redis-cli -h {target} -p {port} INFO 2>/dev/null",
                    timeout=15,
                )
                if info_out:
                    ofile = self.recon_dir / f"redis_{port}_info.txt"
                    with open(ofile, "w") as f:
                        f.write(info_out)
                    info(f"  Redis INFO saved ({len(info_out)} bytes)")

            if pong:
                self.add_finding(
                    "CRITICAL", "Redis",
                    f"Redis on port {port} allows unauthenticated access",
                    f"redis-cli -h {target} -p {port}",
                )
                found(f"Unauth Redis: redis-cli -h {target} -p {port}")
                # Manual notes only — no auto write/config SET (would be exploit path)
                info("Manual next (not auto-run): CONFIG GET dir / KEYS *")
                cmd_hint(f"redis-cli -h {target} -p {port} CONFIG GET dir")
                cmd_hint(f"redis-cli -h {target} -p {port} INFO keyspace")
            else:
                self.add_finding(
                    "INFO", "Redis",
                    f"Redis on port {port} (auth may be required)",
                )

        # ── VNC ────────────────────────────────────────────────────
        elif svc_type == "vnc":
            subsection(f"VNC (port {port})")
            info("VNC detected. Info probe only (no auto-brute)...")

            ofile = self.recon_dir / f"vnc_{port}_nmap.txt"
            # vnc-info only — vnc-brute is spray, not auto-run
            nmap_cmd = f"nmap -sV -p {port} --script vnc-info -oN {ofile} {target}"
            cmd_hint(self._wrap(nmap_cmd))
            stdout, _, _ = run(self._wrap(nmap_cmd), timeout=60)
            actions = [
                {"tool": "vnc_info", "run": True, "reason": "auth requirement probe", "weight": "light"},
                {"tool": "vnc-brute", "run": False, "reason": "banned auto spray", "weight": "heavy"},
            ]
            self._log_decision("vnc", port, actions)

            if "no authentication" in (stdout or "").lower() or "authentication: none" in (stdout or "").lower():
                self.add_finding(
                    "CRITICAL", "VNC",
                    f"VNC on port {port} requires NO authentication!",
                    f"vncviewer {target}:{port}",
                )
                found(f"Connect: vncviewer {target}::{port}")
            else:
                self.add_finding("INFO", "VNC", f"VNC on port {port}")
                cmd_hint(f"vncviewer {target}::{port}")
                # Manual spray hint only
                cmd_hint(f"# manual only: hydra -s {port} -P rockyou.txt {target} vnc")

        # ── TFTP ───────────────────────────────────────────────────
        elif svc_type == "tftp":
            subsection(f"TFTP (port {port})")
            info("TFTP detected. Checking for read/write access...")

            ofile = self.recon_dir / f"tftp_{port}_nmap.txt"
            nmap_cmd = f"nmap -sU -p {port} --script tftp-enum {target} -oN {ofile}"
            cmd_hint(self._wrap(nmap_cmd))
            stdout, _, _ = run(self._wrap(nmap_cmd), timeout=60)

            self.add_finding("WARNING", "TFTP", f"TFTP on port {port} (no auth by design, check read/write)",
                             f"tftp {target} {port}")
            info("TFTP has no authentication. Try reading common files:")
            cmd_hint(f"tftp {target} {port} -c get /etc/passwd")
            cmd_hint(f"tftp {target} {port} -c get boot.ini")
            cmd_hint(f"tftp {target} {port} -c get web.config")
            info("Try writing a webshell:")
            cmd_hint(f"tftp {target} {port} -c put shell.php /var/www/html/shell.php")

        # ── POP3 / IMAP (mail) ────────────────────────────────────
        elif svc_type == "mail":
            mail_svc = extra or "mail"
            subsection(f"Mail Service (port {port}, {mail_svc})")
            info(f"Mail service detected: {mail_svc}")

            ofile = self.recon_dir / f"mail_{port}_nmap.txt"
            scripts = "pop3-capabilities,pop3-ntlm-info,imap-capabilities,imap-ntlm-info"
            nmap_cmd = f"nmap -sV -p {port} --script {scripts} {target} -oN {ofile}"
            cmd_hint(self._wrap(nmap_cmd))
            stdout, _, _ = run(self._wrap(nmap_cmd), timeout=60)

            if "ntlm" in stdout.lower():
                self.add_finding("WARNING", "Mail", f"NTLM info leak on {mail_svc} port {port}")

            self.add_finding("INFO", "Mail", f"{mail_svc} on port {port}")
            info("If you have creds, check for emails:")
            if "pop3" in mail_svc.lower() or port in (110, 995):
                cmd_hint(f"telnet {target} {port}")
                cmd_hint(f"  USER <username>")
                cmd_hint(f"  PASS <password>")
                cmd_hint(f"  LIST / RETR 1")
            else:
                cmd_hint(f"curl -k 'imaps://{target}' --user 'user:pass'")

        # ── rsync ──────────────────────────────────────────────────
        elif svc_type == "rsync":
            subsection(f"rsync (port {port})")
            info("rsync detected. Listing available modules...")

            ofile = self.recon_dir / f"rsync_{port}.txt"
            list_cmd = f"rsync -av --list-only rsync://{target}:{port}/"
            cmd_hint(self._wrap(list_cmd))
            stdout, _, rc = run(self._wrap(list_cmd), timeout=30)

            if stdout:
                with open(ofile, "w") as f:
                    f.write(stdout)
                for line in stdout.splitlines()[:20]:
                    info(f"  {line}")
                self.add_finding("WARNING", "rsync", f"rsync on port {port} lists modules (potential file access)",
                                 f"rsync -av rsync://{target}:{port}/MODULE ./loot/")
                info("Download a module:")
                cmd_hint(f"rsync -av rsync://{target}:{port}/MODULE ./loot/rsync_MODULE/")
            else:
                self.add_finding("INFO", "rsync", f"rsync on port {port} (no modules listed or auth required)")

        # ── Memcached ──────────────────────────────────────────────
        elif svc_type == "memcached":
            subsection(f"Memcached (port {port})")
            info("Memcached detected. Checking for unauthenticated access...")

            ofile = self.recon_dir / f"memcached_{port}.txt"
            nmap_cmd = f"nmap -sV -p {port} --script memcached-info {target} -oN {ofile}"
            cmd_hint(self._wrap(nmap_cmd))
            stdout, _, _ = run(self._wrap(nmap_cmd), timeout=30)

            self.add_finding("WARNING", "Memcached", f"Memcached on port {port} (default: no auth)",
                             f"echo 'stats' | nc {target} {port}")
            info("Dump keys:")
            cmd_hint(f"echo 'stats items' | nc {target} {port}")
            cmd_hint(f"echo 'stats cachedump 1 100' | nc {target} {port}")

        # ── MongoDB ────────────────────────────────────────────────
        elif svc_type == "mongodb":
            subsection(f"MongoDB (port {port})")
            info("MongoDB detected. Checking for unauthenticated access...")

            ofile = self.recon_dir / f"mongodb_{port}_nmap.txt"
            nmap_cmd = f"nmap -sV -p {port} --script mongodb-info,mongodb-databases {target} -oN {ofile}"
            cmd_hint(self._wrap(nmap_cmd))
            stdout, _, _ = run(self._wrap(nmap_cmd), timeout=60)

            if "totalsize" in stdout.lower() or "databases" in stdout.lower():
                self.add_finding("CRITICAL", "MongoDB", f"MongoDB on port {port} allows unauthenticated access!",
                                 f"mongosh --host {target} --port {port}")
                found(f"Connect: mongosh --host {target} --port {port}")
                info("Dump databases:")
                cmd_hint(f"mongosh --host {target} --port {port} --eval 'db.adminCommand({{listDatabases:1}})'")
            else:
                self.add_finding("INFO", "MongoDB", f"MongoDB on port {port}")
                cmd_hint(f"mongosh --host {target} --port {port}")

        # ── CouchDB ────────────────────────────────────────────────
        elif svc_type == "couchdb":
            subsection(f"CouchDB (port {port})")
            info("CouchDB detected. Checking for unauthenticated access...")

            # CouchDB has a REST API
            stdout, _, rc = run(self._wrap(f"curl -s http://{target}:{port}/"), timeout=15)
            if "couchdb" in stdout.lower() or "welcome" in stdout.lower():
                self.add_finding("WARNING", "CouchDB", f"CouchDB REST API accessible on port {port}")

                # List databases
                db_out, _, _ = run(self._wrap(f"curl -s http://{target}:{port}/_all_dbs"), timeout=15)
                if db_out and db_out.startswith("["):
                    self.add_finding("CRITICAL", "CouchDB",
                                     f"CouchDB on port {port} lists databases unauthenticated: {db_out[:100]}",
                                     f"curl http://{target}:{port}/_all_dbs")
                    found(f"Databases: {db_out[:200]}")
                    info("Dump a database:")
                    cmd_hint(f"curl -s http://{target}:{port}/DBNAME/_all_docs?include_docs=true")
            else:
                self.add_finding("INFO", "CouchDB", f"CouchDB on port {port}")

        # ── PostgreSQL ─────────────────────────────────────────────
        elif svc_type == "postgresql":
            subsection(f"PostgreSQL (port {port})")
            info("PostgreSQL detected.")

            ofile = self.recon_dir / f"postgres_{port}_nmap.txt"
            nmap_cmd = f"nmap -sV -p {port} --script pgsql-brute {target} -oN {ofile}"
            cmd_hint(self._wrap(nmap_cmd))
            stdout, _, _ = run(self._wrap(nmap_cmd), timeout=120)

            self.add_finding("INFO", "PostgreSQL", f"PostgreSQL on port {port}")
            info("Try default creds:")
            cmd_hint(f"psql -h {target} -p {port} -U postgres")
            cmd_hint(f"hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/best1050.txt {target} -s {port} postgres")
            info("If authenticated, check for RCE:")
            cmd_hint(f"psql -h {target} -U postgres -c \"COPY (SELECT 'id') TO PROGRAM 'id';\"")


        elif svc_type == "telnet":
            pdir = port_recon_subdir(self.recon_dir, port, "tcp")
            subsection(f"Telnet (port {port})")
            info("Telnet detected. Banner grab only (enum; no auto-login spray).")
            ofile = pdir / "telnet_banner.txt"
            nmap_out = self.recon_dir / f"nmap_telnet_{port}.txt"
            run(
                f"nmap {self.ping_flag} -p {port} --script 'telnet-ntlm-info,banner' "
                f"-oN {nmap_out} {target} 2>/dev/null",
                timeout=45,
            )
            if nmap_out.exists():
                content = nmap_out.read_text(errors="replace")
                ofile.write_text(content, encoding="utf-8")
                for line in content.splitlines()[:20]:
                    if line.strip():
                        info(f"  {line.strip()}")
            else:
                stdout, _, _ = run(
                    f"timeout 3 bash -c 'echo | nc -nvw 2 {target} {port} 2>&1' | head -10",
                    timeout=8,
                )
                if stdout:
                    ofile.write_text(stdout, encoding="utf-8")
                    info(f"  Banner: {stdout[:200]}")
            self.add_finding("INFO", "Telnet", f"Telnet open on port {port}")
            cmd_hint(f"telnet {target} {port}")

        elif svc_type == "elasticsearch":
            pdir = port_recon_subdir(self.recon_dir, port, "tcp")
            subsection(f"Elasticsearch (port {port})")
            info("Elasticsearch detected. Unauth cluster enum only (no write).")
            base = f"http://{target}:{port}"
            for path_es, label in [
                ("/", "root"),
                ("/_cat/indices?v", "indices"),
                ("/_cluster/health?pretty", "health"),
                ("/_nodes?pretty", "nodes"),
            ]:
                ofile = pdir / f"es_{label}.txt"
                stdout, _, rc = run(
                    f"curl -sk --max-time 8 '{base}{path_es}' 2>/dev/null",
                    timeout=12,
                )
                if stdout:
                    ofile.write_text(stdout, encoding="utf-8")
                    info(f"  {label}: {stdout[:120].replace(chr(10), ' ')}")
                    low = stdout.lower()
                    if label == "indices" and (
                        "green" in low or "yellow" in low or "index" in low
                    ):
                        self.add_finding(
                            "WARNING", "Elasticsearch",
                            f"ES indices listed unauthenticated on {port}",
                            f"curl -s '{base}/_cat/indices?v'",
                        )
                    if label == "root" and "cluster_name" in stdout:
                        self.add_finding(
                            "WARNING", "Elasticsearch",
                            f"Elasticsearch API open on port {port}",
                            f"curl -s '{base}/'",
                        )
            cmd_hint(f"curl -s http://{target}:5601/api/status")

        elif svc_type == "kibana":
            pdir = port_recon_subdir(self.recon_dir, port, "tcp")
            subsection(f"Kibana (port {port})")
            info("Kibana detected. Status probe only.")
            for path_k, label in [("/", "root"), ("/api/status", "status"), ("/app/kibana", "app")]:
                url = f"http://{target}:{port}{path_k}"
                ofile = pdir / f"kibana_{label}.txt"
                stdout, _, _ = run(f"curl -skI --max-time 8 '{url}' 2>/dev/null", timeout=12)
                body, _, _ = run(
                    f"curl -sk --max-time 8 '{url}' 2>/dev/null | head -c 1500",
                    timeout=12,
                )
                blob = (stdout or "") + "\n" + (body or "")
                if blob.strip():
                    ofile.write_text(blob, encoding="utf-8")
            self.add_finding("INFO", "Kibana", f"Kibana port {port} reachable")
            cmd_hint(f"curl -s http://{target}:{port}/api/status")


        # Run any plugin commands defined in cantina.toml for this service
        url = None
        if svc_type == "http" and extra:
            url = f"{extra}://{target}:{port}"
        self._run_plugin_commands(svc_type, port, url=url)

    # ── Summary ────────────────────────────────────────────────────────

    def print_summary(self):
        section("SCAN SUMMARY")

        # Port summary
        subsection("Discovered Services")
        all_ports = {**self.tcp_ports, **self.udp_ports}
        if all_ports:
            for p in sorted(all_ports.values(), key=lambda x: x["port"]):
                proto_label = p["proto"].upper()
                svc = f"{p['service']}" + (f" {p['version']}" if p['version'] else "")
                good(f"{C.W}{p['port']}/{proto_label:<4}{C.RST} {svc}")
        else:
            warn("No open ports discovered")

        # TUI findings dashboard
        ui.summary()

        # Next steps
        subsection("Suggested Next Steps")
        if any(p["service"] in ("http", "https", "ssl/http") for p in all_ports.values()):
            out(f"  {C.C}1.{C.RST} Browse web services, check for login panels")
            out(f"  {C.C}2.{C.RST} Check feroxbuster/nikto output in {C.W}{self.recon_dir}/")
        if 88 in all_ports:
            out(f"  {C.C}3.{C.RST} This is a DC. Run: {C.W}python3 ackbar.py -d DOMAIN -u USER -p PASS -dc {self.target}")
        if 445 in all_ports or 139 in all_ports:
            out(f"  {C.C}4.{C.RST} Check SMB: {C.W}python3 jawa.py {self.target}")
        if self.os_guess == "Linux/Unix":
            out(f"  {C.C}5.{C.RST} After shell: transfer leia.py for privesc enum")
        elif self.os_guess == "Windows":
            out(f"  {C.C}5.{C.RST} After shell: transfer sidious.ps1 for privesc enum")

    def save_json(self, path):
        data = {
            "tool": "Cantina",
            "version": VERSION,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "target": self.target,
            "os_guess": self.os_guess,
            "recon_depth": getattr(self, "recon_depth", "normal"),
            "tcp_ports": self.tcp_ports,
            "udp_ports": self.udp_ports,
            "findings": self.findings,
            "decisions": getattr(self, "decision_log", []),
            "summary": {
                "tcp_count": len(self.tcp_ports),
                "udp_count": len(self.udp_ports),
                "critical": len([f for f in self.findings if f["severity"] == "CRITICAL"]),
                "warning": len([f for f in self.findings if f["severity"] == "WARNING"]),
                "decision_services": len(getattr(self, "decision_log", []) or []),
                "tools_run": sum(
                    len(d.get("ran") or [])
                    for d in (getattr(self, "decision_log", []) or [])
                ),
                "tools_skipped": sum(
                    len(d.get("skipped") or [])
                    for d in (getattr(self, "decision_log", []) or [])
                ),
            }
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def write_manual_commands(self):
        """Write _manual_commands.txt from all cmd_hint() calls during the scan."""
        collected = get_collected_cmds()
        if not collected:
            return
        path = self.outdir / "_manual_commands.txt"
        grouped = {}
        for section_name, cmd in collected:
            grouped.setdefault(section_name, []).append(cmd)
        with open(path, "w") as f:
            f.write(f"# Manual Commands - {self.target}\n")
            f.write(f"# Generated by Cantina v{VERSION} at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Copy-paste these for follow-up enumeration\n\n")
            for sec, cmds in grouped.items():
                f.write(f"## {sec}\n")
                for c in cmds:
                    f.write(f"{c}\n")
                f.write("\n")
        info(f"Manual commands saved to {C.W}{path}")
        reset_collected_cmds()

    def extract_patterns(self, text, source="unknown"):
        """Scan text for high-value patterns (usernames, passwords, hashes, etc.)."""
        if not text:
            return
        seen = set()
        for category, regexes in self._pattern_regexes.items():
            for rx in regexes:
                for m in rx.finditer(text):
                    value = m.group(0) if not m.lastindex else m.group(m.lastindex)
                    value = value.strip().strip("'\"")
                    if not value or len(value) < 2 or len(value) > 500:
                        continue
                    key = (category, value)
                    if key not in seen:
                        seen.add(key)
                        self._patterns.append((category, value, source))

    def write_patterns(self):
        """Write _patterns.log with all extracted patterns from tool output."""
        if not self._patterns:
            return
        path = self.outdir / "_patterns.log"
        grouped = {}
        for cat, val, src in self._patterns:
            grouped.setdefault(cat, []).append((val, src))
        # Deduplicate within each category
        with open(path, "w") as f:
            f.write(f"# Pattern Extraction - {self.target}\n")
            f.write(f"# Generated by Cantina v{VERSION} at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {len(self._patterns)} matches across {len(grouped)} categories\n\n")
            for cat in sorted(grouped.keys()):
                f.write(f"## {cat}\n")
                deduped = {}
                for val, src in grouped[cat]:
                    if val not in deduped:
                        deduped[val] = src
                for val, src in deduped.items():
                    f.write(f"  {val}  (from: {src})\n")
                f.write("\n")
        info(f"Pattern matches saved to {C.W}{path} ({len(self._patterns)} hits)")


# ── Plugin Config ─────────────────────────────────────────────────────

def _build_plugin_registry(plugins_dir=None, toml_config=None, skip=False):
    """Discover disk plugins + fold legacy toml command plugins into one registry."""
    try:
        from cantina_plugins import (
            PluginRegistry,
            discover_plugins,
            toml_commands_as_plugins,
        )
    except ImportError:
        return None
    if skip:
        return PluginRegistry()
    reg = discover_plugins(plugins_dir)
    if toml_config:
        toml_commands_as_plugins(toml_config, reg)
    return reg


def _load_plugin_config(config_path=None):
    """Load cantina.toml plugin config. Returns dict of service -> commands list, or empty dict."""
    paths_to_try = []
    if config_path:
        paths_to_try.append(config_path)
    paths_to_try.extend([
        "cantina.toml",
        os.path.expanduser("~/.config/cantina.toml"),
        os.path.expanduser("~/tools/cantina.toml"),
    ])

    for p in paths_to_try:
        if os.path.isfile(p):
            try:
                # Python 3.11+ has tomllib, fall back to manual parsing for older
                try:
                    import tomllib
                    with open(p, "rb") as f:
                        data = tomllib.load(f)
                except ImportError:
                    try:
                        import tomli as tomllib
                        with open(p, "rb") as f:
                            data = tomllib.load(f)
                    except ImportError:
                        # Minimal TOML parser for our simple format
                        data = _parse_simple_toml(p)
                info(f"Plugin config loaded: {C.W}{p}")
                return data
            except Exception as e:
                warn(f"Failed to load plugin config {p}: {e}")
                return {}
    return {}


def _parse_simple_toml(path):
    """Minimal TOML parser that handles [section] + commands = [...] arrays."""
    data = {}
    current_section = None
    with open(path) as f:
        content = f.read()

    # Remove comments
    lines = []
    for line in content.splitlines():
        stripped = line.split("#")[0].rstrip()
        lines.append(stripped)
    text = "\n".join(lines)

    # Parse sections and their commands arrays
    section_re = re.compile(r'^\[([^\]]+)\]', re.MULTILINE)
    sections = list(section_re.finditer(text))

    for i, m in enumerate(sections):
        name = m.group(1).strip()
        start = m.end()
        end = sections[i+1].start() if i+1 < len(sections) else len(text)
        block = text[start:end]

        # Extract commands = [ "...", "..." ]
        cmd_match = re.search(r'commands\s*=\s*\[(.*?)\]', block, re.DOTALL)
        if cmd_match:
            raw = cmd_match.group(1)
            cmds = re.findall(r'"([^"]*)"', raw)
            data[name] = {"commands": cmds}

    return data


# ════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Cantina v1.3.3 - OSCP Network Recon Orchestrator (concurrent multi-target, force-services, timeouts)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python3 cantina.py 10.10.10.5\n"
               "  python3 cantina.py 10.10.10.5 -t all\n"
               "  python3 cantina.py 10.10.10.5 -t deep --background   # long-running\n"
               "  python3 cantina.py --status -o ./cantina/10.10.10.5\n"
               "  python3 cantina.py 10.10.10.0/24 -t network\n"
               "  python3 cantina.py 10.10.10.5 -t all --resume -j\n"
               "\n"
               "deep = full OSCP-legal enum pipeline (quick→full→udp→vuln→recon)\n"
               "       with phase status file; --background detaches so short tools\n"
               "       (jawa/jarjar/…) can run while deep continues.\n"
               "Enumeration only. No exploitation. OSCP exam safe."
    )
    parser.add_argument("target", nargs="?", help="Target IP, hostname, or CIDR (for network scan)")
    parser.add_argument("-T", "--targets", help="File with one target per line (multi-target mode)")
    parser.add_argument("-t", "--type", default="quick",
                        choices=["quick", "full", "udp", "vuln", "recon", "network", "all", "deep"],
                        help="Scan type (default: quick). deep = long full pipeline with status")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-j", "--json", action="store_true", help="Save JSON summary")
    parser.add_argument("-q", "--quiet", action="store_true", help="No banner")
    parser.add_argument("--rate", type=int, default=4, choices=range(1, 6), help="Nmap timing (1-5, default 4)")
    parser.add_argument("--resume", action="store_true", help="Skip scans with existing output")
    parser.add_argument("--skip-recon", action="store_true", help="Skip service recon dispatch")
    parser.add_argument("--skip-udp", action="store_true", help="Skip UDP scan")
    parser.add_argument("--skip-vuln", action="store_true", help="Skip vuln scan")
    parser.add_argument("--skip-sploit", action="store_true", help="Skip searchsploit lookup")
    parser.add_argument("--findings", help="Append findings to shared JSONL file")
    parser.add_argument("-e", "--engage", default=None,
                       help="Override engage log directory (default: ~/.psk/engage/)")
    parser.add_argument("--no-log", action="store_true", help="Disable auto-logging")
    parser.add_argument("--config", help="Path to cantina.toml plugin config")
    parser.add_argument(
        "--plugins-dir",
        default=None,
        help="Directory of Cantina enum plugins (*.py with PLUGIN meta + match/run)",
    )
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="List discovered plugins and exit (no scan required)",
    )
    parser.add_argument(
        "--skip-plugins",
        action="store_true",
        help="Skip custom plugin phase (built-in recon only)",
    )
    parser.add_argument("--no-html", action="store_true",
                        help="Skip HTML report generation (default: always generated)")
    parser.add_argument(
        "--background",
        action="store_true",
        help="Detach deep/all scan to background (writes PID + deep_status.json; returns immediately)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print deep_status.json for -o DIR (or default outdir) and exit",
    )
    parser.add_argument(
        "--max-workers", type=int, default=3,
        help="Concurrent multi-target workers (default 3; single-target ignores)",
    )
    parser.add_argument(
        "--timeout", type=float, default=None, metavar="MIN",
        help="Global run timeout in minutes (abandon remaining targets when hit)",
    )
    parser.add_argument(
        "--target-timeout", type=float, default=None, metavar="MIN",
        help="Per-target timeout in minutes (abandon hung host, continue others)",
    )
    parser.add_argument(
        "--force-services", nargs="+", default=None, metavar="SPEC",
        help="Seed known services and skip rediscovery (e.g. tcp/80/http tcp/445/smb)",
    )
    parser.add_argument(
        "--ports", default=None, metavar="LIST",
        help="Known open ports (skip full rediscovery). e.g. 80,443,T:22,U:53",
    )
    parser.add_argument(
        "--dirbust-tool", choices=["feroxbuster", "ffuf", "gobuster"], default=None,
        help="Preferred directory-busting tool",
    )
    parser.add_argument(
        "--dirbust-wordlist", nargs="+", default=None, metavar="PATH",
        help="Wordlist path(s) for dirbust",
    )
    parser.add_argument(
        "--dirbust-threads", type=int, default=None,
        help="Dirbust thread count",
    )
    parser.add_argument(
        "--dirbust-ext", default=None, metavar="EXTS",
        help="Dirbust extensions without dots (comma-separated, e.g. php,txt,html)",
    )
    parser.add_argument(
        "--vhost-domain", default=None,
        help="Base hostname for virtual-host enumeration",
    )
    parser.add_argument(
        "--subdomain-domain", default=None,
        help="Base domain for subdomain enumeration",
    )
    parser.add_argument(
        "--vhost-wordlist", default=None,
        help="Wordlist for virtual-host enumeration",
    )
    parser.add_argument(
        "--subdomain-wordlist", default=None,
        help="Wordlist for subdomain enumeration",
    )
    args = parser.parse_args()

    # Status-only path (no target required if -o given)
    if args.status:
        out = args.output or (f"./cantina/{args.target}" if args.target else None)
        if not out:
            parser.error("--status requires -o DIR or a target")
        _print_deep_status(out)
        return

    # Load plugin config if available
    args._plugin_config = _load_plugin_config(args.config)

    # Discover first-class plugins (disk + legacy toml commands)
    args._plugin_registry = _build_plugin_registry(
        plugins_dir=getattr(args, "plugins_dir", None),
        toml_config=args._plugin_config,
        skip=bool(getattr(args, "skip_plugins", False)),
    )

    # List plugins and exit (no target / no scan)
    if getattr(args, "list_plugins", False):
        try:
            from cantina_plugins import format_plugin_list
            print(format_plugin_list(args._plugin_registry))
        except ImportError:
            print("[-] cantina_plugins module not available")
            sys.exit(1)
        return

    # Resolve target list
    if args.targets:
        if not os.path.isfile(args.targets):
            print(f"[-] Targets file not found: {args.targets}")
            sys.exit(1)
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not targets:
            print("[-] Targets file is empty")
            sys.exit(1)
    elif args.target:
        targets = [args.target]
    else:
        parser.error("Either TARGET or -T TARGETS_FILE is required (or use --list-plugins)")

    # Validate all targets upfront (shared validate_target — no shell metacharacters)
    for t in targets:
        if not validate_target(t):
            print(f"[-] Invalid target: {t}")
            print("    Must be an IP address, CIDR range, or hostname (alphanumeric/dots/hyphens)")
            sys.exit(1)

    if len(targets) > 1:
        print(f"[*] Multi-target mode: {len(targets)} targets loaded from {args.targets}")

    # Background: only for deep/all single-target (detach before scan work)
    if args.background:
        if args.type not in ("deep", "all"):
            print("[-] --background requires -t deep (or -t all)")
            sys.exit(2)
        if len(targets) != 1:
            print("[-] --background supports a single target (not -T multi)")
            sys.exit(2)
        target = targets[0]
        target_clean = target.replace("/", "_").replace(":", "_")
        outdir = args.output or f"./cantina/{target_clean}"
        Path(outdir).mkdir(parents=True, exist_ok=True)
        # Rebuild argv without --background for child
        child_args = []
        skip_next = False
        for a in sys.argv[1:]:
            if skip_next:
                skip_next = False
                continue
            if a in ("--background",):
                continue
            child_args.append(a)
        # Ensure -o outdir and -t deep are explicit for the child
        if "-o" not in child_args and "--output" not in child_args:
            child_args.extend(["-o", outdir])
        if "-t" not in child_args and "--type" not in child_args:
            child_args.extend(["-t", "deep"])
        elif args.type == "all":
            # keep all, or promote to deep for status tracking
            pass
        # Force resume-friendly deep with json
        if "-j" not in child_args and "--json" not in child_args:
            child_args.append("-j")
        if "--resume" not in child_args:
            child_args.append("--resume")
        _detach_background(child_args)
        return


    # Timeouts (minutes -> seconds)
    global_timeout_sec = (
        float(args.timeout) * 60.0 if getattr(args, "timeout", None) else None
    )
    target_timeout_sec = (
        float(args.target_timeout) * 60.0 if getattr(args, "target_timeout", None) else None
    )
    max_workers = max(1, int(getattr(args, "max_workers", 3) or 3))
    if len(targets) == 1:
        max_workers = 1

    # Shared global budget start for concurrent workers (immutable timing base)
    global _shared_global_start, _shared_global_timeout_sec
    _shared_global_start = time.monotonic()
    _shared_global_timeout_sec = global_timeout_sec
    scheduling_clock = DeadlineClock(
        global_timeout_sec=global_timeout_sec,
        target_timeout_sec=target_timeout_sec,
        global_start=_shared_global_start,
    )

    def _process_one_target(target, target_timeout_sec=None):
        """Run full pipeline for one target (used by concurrent multi-target).

        Thread-local audit + deadline only. Never assigns module globals for
        those sinks (avoids cross-host _commands.log contamination).
        """
        # Per-target clock shares global start; own target_start
        t_budget = target_timeout_sec
        if t_budget is None:
            t_budget = scheduling_clock.target_timeout_sec
        elif not isinstance(t_budget, (int, float)):
            t_budget = scheduling_clock.target_timeout_sec
        local_clock = DeadlineClock(
            global_timeout_sec=_shared_global_timeout_sec,
            target_timeout_sec=t_budget,
            global_start=_shared_global_start,
        )
        local_clock.begin_target()
        set_deadline_clock(local_clock)
        reset_collected_cmds()

        engage_start("cantina", target, engage_dir=args.engage)
        target_clean = target.replace("/", "_").replace(":", "_")
        base_dir = args.output or "./cantina"
        outdir = (
            os.path.join(base_dir, target_clean)
            if len(targets) > 1
            else (args.output or f"./cantina/{target_clean}")
        )
        Path(outdir).mkdir(parents=True, exist_ok=True)

        audit = CommandAuditLog(Path(outdir) / "_commands.log")
        set_command_audit(audit)

        fc = None
        if args.findings:
            fc = FindingsCollector(tool="cantina", host=target, output=args.findings)

        # Shallow-copy args so concurrent workers do not stomp .target
        import copy
        targs = copy.copy(args)
        targs.target = target

        scanner = Scanner(target, outdir, rate=args.rate, resume=args.resume, fc=fc)
        scanner.plugin_config = args._plugin_config
        scanner.plugin_registry = getattr(args, "_plugin_registry", None)
        scanner.dirbust_tool = getattr(args, "dirbust_tool", None)
        scanner.dirbust_wordlists = list(getattr(args, "dirbust_wordlist", None) or [])
        scanner.dirbust_threads = getattr(args, "dirbust_threads", None)
        scanner.dirbust_ext = getattr(args, "dirbust_ext", None)
        scanner.vhost_domain = getattr(args, "vhost_domain", None)
        scanner.subdomain_domain = getattr(args, "subdomain_domain", None)
        scanner.vhost_wordlist = getattr(args, "vhost_wordlist", None)
        scanner.subdomain_wordlist = getattr(args, "subdomain_wordlist", None)

        # Seed known ports/services (skip rediscovery)
        force = getattr(args, "force_services", None)
        ports_spec = getattr(args, "ports", None)
        if force or ports_spec:
            scanner.apply_known_ports(force, ports_spec)
            info(f"Seeded ports from force-services/ports (skip rediscovery={scanner.skip_port_discovery})")

        log_path = os.path.join(outdir, "cantina.log")
        with _ui_lock:
            ui.outfile = open(log_path, "w")
            ui.start_time = time.time()
            start_time = ui.start_time

        try:
            if local_clock.expired():
                raise TimeoutError("target deadline expired before run")
            _cantina_run(targs, scanner, outdir, start_time=start_time)
            # Final budget check so soft mid-pipeline work cannot mark ok late
            if local_clock.expired():
                raise TimeoutError("deadline expired")
            return {"outdir": outdir, "target": target}
        finally:
            with _ui_lock:
                if ui.outfile:
                    try:
                        ui.outfile.close()
                    except Exception:
                        pass
                    ui.outfile = None
            if fc:
                try:
                    fc.close()
                except Exception:
                    pass
            if not getattr(args, "no_html", False):
                try:
                    from report import build_html_report
                    report_path = build_html_report(
                        scanner, outdir, targs,
                        start_time=start_time,
                        end_time=time.time(),
                    )
                    print(f"\n[+] HTML report: {report_path}")
                except Exception as e:
                    print(f"\n[!] HTML report generation failed: {e}")
            set_command_audit(None)
            set_deadline_clock(None)

    if len(targets) > 1:
        print(f"[*] Concurrent multi-target: {len(targets)} hosts, workers={max_workers}")
        if global_timeout_sec:
            print(f"[*] Global timeout: {args.timeout} min")
        if target_timeout_sec:
            print(f"[*] Per-target timeout: {args.target_timeout} min")

    results = run_multi_targets(
        targets,
        _process_one_target,
        max_workers=max_workers,
        global_timeout_sec=global_timeout_sec,
        target_timeout_sec=target_timeout_sec,
        clock=scheduling_clock,
    )
    for r in results:
        st = r.get("status")
        if st != "ok":
            print(f"[!] target {r.get('target')}: {st} {r.get('error') or ''}")


def _deep_status_path(outdir):
    return Path(outdir) / "deep_status.json"


def _write_deep_status(outdir, **fields):
    """Atomic-ish phase status so short tools can poll progress while deep runs."""
    path = _deep_status_path(outdir)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing.update(fields)
    existing["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    existing.setdefault("schema", "cantina_deep_status/v1")
    existing.setdefault("legal", "enumeration-only; OSCP-safe; no exploit/spray/payload delivery")
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    tmp.replace(path)


def _print_deep_status(outdir):
    path = _deep_status_path(outdir)
    if not path.exists():
        print(f"[-] No deep_status.json under {outdir}")
        sys.exit(1)
    data = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(data, indent=2))
    pid = data.get("pid")
    state = data.get("state", "?")
    phase = data.get("phase", "?")
    print(f"\n[*] state={state} phase={phase} pid={pid}")
    if pid:
        try:
            os.kill(int(pid), 0)
            print(f"[+] process {pid} still running")
        except OSError:
            print(f"[!] process {pid} not running (stale PID or finished)")


def _detach_background(argv_without_bg):
    """Re-exec without --background; redirect logs; write PID; exit parent."""
    # Build child argv: drop --background, force deep/all style resume-friendly
    child_argv = [a for a in argv_without_bg if a != "--background"]
    # Ensure we log: user still gets outdir from -o
    outdir_hint = None
    if "-o" in child_argv:
        i = child_argv.index("-o")
        if i + 1 < len(child_argv):
            outdir_hint = child_argv[i + 1]
    # Child inherits cwd; log to outdir after scanner creates it — use temp then
    log_path = Path(outdir_hint or ".") / "cantina_deep.log"
    if outdir_hint:
        Path(outdir_hint).mkdir(parents=True, exist_ok=True)
    # Windows + POSIX detach
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        # DETACHED_PROCESS = 0x00000008, CREATE_NEW_PROCESS_GROUP = 0x00000200
        creationflags = 0x00000008 | 0x00000200

    logf = open(log_path, "a", encoding="utf-8")
    logf.write(f"\n--- deep start {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
    logf.flush()
    popen_kwargs = {
        "args": [sys.executable, str(Path(__file__).resolve())] + child_argv,
        "stdin": subprocess.DEVNULL,
        "stdout": logf,
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = creationflags
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(**popen_kwargs)
    # Write provisional status
    if outdir_hint:
        _write_deep_status(
            outdir_hint,
            state="running",
            phase="starting",
            pid=proc.pid,
            log=str(log_path),
            mode="background",
        )
        pidfile = Path(outdir_hint) / "cantina_deep.pid"
        pidfile.write_text(str(proc.pid), encoding="utf-8")
    print(f"[+] Cantina deep detached pid={proc.pid}")
    print(f"[+] Log: {log_path}")
    if outdir_hint:
        print(f"[+] Status: python cantina.py --status -o {outdir_hint}")
    print("[*] Short tools (jawa/jarjar/ackbar/…) can run now while deep continues.")
    return proc.pid


def _run_deep_pipeline(args, scanner, outdir):
    """Long-running OSCP-legal enum pipeline with phase status checkpoints.

    Phases (all enumeration):
      1 quick → 2 full_tcp → 3 udp → 4 vuln+searchsploit → 5 recon → 6 finalize
    """
    scanner.recon_depth = "deep"
    phases_done = []

    def mark(phase, **extra):
        phases_done.append(phase)
        _write_deep_status(
            outdir,
            state="running",
            phase=phase,
            phases_done=list(phases_done),
            pid=os.getpid(),
            target=args.target,
            ports_tcp=len(getattr(scanner, "tcp_ports", {}) or {}),
            ports_udp=len(getattr(scanner, "udp_ports", {}) or {}),
            findings=len(getattr(scanner, "findings", []) or []),
            **extra,
        )
        info(f"Deep phase complete: {C.W}{phase}")

    mark("init")
    # Phase 1: quick top ports + scripts
    scanner.quick_scan()
    mark("quick")

    # Phase 2+3: full TCP and optional UDP
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {"full": pool.submit(scanner.full_scan)}
        if not args.skip_udp:
            futures["udp"] = pool.submit(scanner.udp_scan)
        for name, fut in futures.items():
            try:
                fut.result()
                mark(name)
            except Exception as e:
                warn(f"Deep phase {name} error: {e}")
                mark(f"{name}_error", error=str(e))

    # Phase 4: vuln scripts + exploit-db lookup (lookup only)
    if not args.skip_vuln:
        try:
            scanner.vuln_scan()
            mark("vuln")
        except Exception as e:
            warn(f"Deep vuln error: {e}")
            mark("vuln_error", error=str(e))
    if not args.skip_sploit:
        try:
            scanner.searchsploit_scan()
            mark("searchsploit")
        except Exception as e:
            warn(f"Deep searchsploit error: {e}")
            mark("searchsploit_error", error=str(e))

    # Phase 5: service recon dispatch (sibling enum tools)
    if not args.skip_recon:
        try:
            _write_deep_status(
                outdir,
                state="running",
                phase="recon",
                phases_done=list(phases_done),
                pid=os.getpid(),
                target=args.target,
                ports_tcp=len(getattr(scanner, "tcp_ports", {}) or {}),
                ports_udp=len(getattr(scanner, "udp_ports", {}) or {}),
                findings=len(getattr(scanner, "findings", []) or []),
            )
            scanner.service_recon()
            mark("recon")
        except Exception as e:
            warn(f"Deep recon error: {e}")
            mark("recon_error", error=str(e))
    else:
        mark("recon_skipped")

    mark("finalize")


def _cantina_run(args, scanner, outdir, start_time):
    start = start_time

    # Track deep status from the start for foreground deep/all --background child
    if args.type in ("deep", "all") or getattr(args, "_deep_track", False):
        _write_deep_status(
            outdir,
            state="running",
            phase="boot",
            pid=os.getpid(),
            target=args.target,
            scan_type=args.type,
        )

    if not args.quiet:
        show_banner()

    section("TARGET INFORMATION")
    info(f"Target:    {C.W}{args.target}")
    info(f"Scan type: {C.W}{args.type}")
    info(f"Output:    {C.W}{outdir}")
    info(f"Rate:      {C.W}T{args.rate}")
    info(f"Resume:    {C.W}{'yes' if args.resume else 'no'}")

    # Host liveness: skip dead ICMP wait when ports were force-seeded
    skip_disc = bool(getattr(scanner, "skip_port_discovery", False))
    if skip_disc:
        scanner.ping_flag = "-Pn"
        scanner.os_guess = "unknown"
        info("Seeded ports — skipping ping probe (using -Pn)")
    else:
        scanner.os_guess, alive = guess_os_from_ttl(args.target)
        if alive:
            good(f"Target is up (OS guess: {C.W}{scanner.os_guess}{C.G})")
        else:
            warn(f"Target not responding to ping, using -Pn")
            scanner.ping_flag = "-Pn"

    # ── Network sweep ──────────────────────────────────────────────
    if args.type == "network":
        hosts = scanner.network_sweep(args.target)
        info(f"{len(hosts)} live hosts found")
        ui.footer(f"Output: {outdir}/")
        if ui.outfile:
            ui.outfile.close()
        return

    # ── Single target scans ────────────────────────────────────────
    # skip_disc already computed above (ping skip)
    if skip_disc:
        info(
            f"Skipping rediscovery — using seeded ports "
            f"(tcp={len(scanner.tcp_ports)} udp={len(scanner.udp_ports)})"
        )
        # Ensure per-port recon dirs exist for known ports
        for p, rec in {**scanner.tcp_ports, **scanner.udp_ports}.items():
            port_recon_subdir(scanner.recon_dir, p, rec.get("proto") or "tcp")

    if args.type == "quick":
        if not skip_disc:
            scanner.quick_scan()

    elif args.type == "full":
        if not skip_disc:
            scanner.quick_scan()
            scanner.full_scan()

    elif args.type == "udp":
        if not skip_disc:
            scanner.udp_scan()

    elif args.type == "vuln":
        if not skip_disc:
            scanner.quick_scan()
        scanner.vuln_scan()
        if not args.skip_sploit:
            scanner.searchsploit_scan()

    elif args.type == "recon":
        if not skip_disc:
            scanner.quick_scan()
        scanner.service_recon()
        if not args.skip_sploit:
            scanner.searchsploit_scan()

    elif args.type == "all":
        if skip_disc:
            if not args.skip_vuln:
                scanner.vuln_scan()
            if not args.skip_sploit:
                scanner.searchsploit_scan()
            if not args.skip_recon:
                scanner.service_recon()
        else:
            # Phase 1: Quick scan (need ports before anything else)
            scanner.quick_scan()

            # Phase 2: Full TCP + UDP in parallel
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(scanner.full_scan)]
                if not args.skip_udp:
                    futures.append(pool.submit(scanner.udp_scan))
                for f in as_completed(futures):
                    try:
                        f.result()
                    except Exception as e:
                        warn(f"Parallel scan error: {e}")

            # Phase 3: Vuln scan + searchsploit
            if not args.skip_vuln:
                scanner.vuln_scan()
            if not args.skip_sploit:
                scanner.searchsploit_scan()

            # Phase 4: Service recon
            if not args.skip_recon:
                scanner.service_recon()

    elif args.type == "deep":
        if skip_disc:
            # Deep without rediscovery: vuln + recon only (enum)
            if not args.skip_vuln:
                scanner.vuln_scan()
            if not args.skip_sploit:
                scanner.searchsploit_scan()
            if not args.skip_recon:
                scanner.service_recon()
        else:
            # Long-running background-friendly pipeline (same legal scope as all)
            _run_deep_pipeline(args, scanner, outdir)

    # Summary
    scanner.print_summary()
    scanner.write_manual_commands()
    scanner.write_patterns()

    # Decision log summary (if recon ran)
    if getattr(scanner, "decision_log", None):
        n_run = sum(len(d.get("ran") or []) for d in scanner.decision_log)
        n_skip = sum(len(d.get("skipped") or []) for d in scanner.decision_log)
        info(
            f"Decision branches: {len(scanner.decision_log)} services, "
            f"{n_run} tools run, {n_skip} skipped"
        )
        dpath = Path(outdir) / "recon" / "decision_log.jsonl"
        if dpath.exists():
            info(f"Decision log: {C.W}{dpath}")

    # JSON output (always for deep so scorecard can consume)
    if args.json or args.type == "deep":
        json_path = os.path.join(outdir, "cantina.json")
        scanner.save_json(json_path)
        info(f"JSON saved to {C.W}{json_path}")

    # Score snapshot for deep runs (offline scorecard)
    if args.type == "deep":
        try:
            from cantina_score import score_scan, write_score
            ports = {**getattr(scanner, "tcp_ports", {}), **getattr(scanner, "udp_ports", {})}
            sc = score_scan(
                ports,
                getattr(scanner, "findings", []),
                label="deep_final",
                mode="deep",
                extra={"target": args.target, "outdir": outdir},
            )
            write_score(Path(outdir) / "cantina_score.json", sc)
            _write_deep_status(
                outdir,
                state="complete",
                phase="done",
                score=sc.get("metrics"),
                ports_tcp=len(scanner.tcp_ports),
                ports_udp=len(scanner.udp_ports),
                findings=len(scanner.findings),
            )
        except Exception as e:
            warn(f"Score snapshot failed: {e}")
            _write_deep_status(outdir, state="complete", phase="done", score_error=str(e))

    info(f"Output: {C.W}{outdir}/")
    ui.footer("Cantina: where every scan tells a story.")

    # Auto-log
    engage_end()


if __name__ == "__main__":
    # Background detach must happen before heavy main() target loop setup
    # when --background is present (handled inside main after parse).
    main()
