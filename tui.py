"""
tui.py - Shared Terminal UI for the OSCP toolkit.
Rich-quality output using only Python stdlib. No pip install needed.

Usage:
    from tui import UI
    ui = UI(title="CANTINA", version="1.0.0", outfile=open("log.txt","w"))
    ui.banner(ASCII_ART)
    with ui.spinner("Scanning") as s:
        s.update("Found 22/tcp")
    ui.summary()

Color hierarchy (deliberate):
    RED        = things to exploit (CRIT, HIGH, exploit commands, found arrows)
    YELLOW     = things to investigate (WARN, MED)
    GREEN      = safe / positive (good checks, tool completion, commands to run)
    WHITE BOLD = key data (hostnames, ports, usernames, counts)
    CYAN       = structural (section headers, info bullets, progress)
    MAGENTA    = subsection headers
    DIM GRAY   = context (timestamps, notes, box borders, dim text)
"""

import sys
import os
import re
import time
import json
import threading
from contextlib import contextmanager
from datetime import datetime

# ── ANSI ────────────────────────────────────────────────────────────────

class Color:
    """ANSI color codes. Disabled if not a TTY."""
    def __init__(self):
        t = sys.stdout.isatty()
        # Core palette
        self.R     = '\033[0;31m'   if t else ''   # Red (danger, exploit)
        self.G     = '\033[0;32m'   if t else ''   # Green (safe, commands)
        self.Y     = '\033[0;33m'   if t else ''   # Yellow (warning)
        self.B     = '\033[0;34m'   if t else ''   # Blue (low severity)
        self.M     = '\033[0;35m'   if t else ''   # Magenta (subsections)
        self.C     = '\033[0;36m'   if t else ''   # Cyan (structure, info)
        self.W     = '\033[1;37m'   if t else ''   # White bold (key data)
        self.D     = '\033[0;90m'   if t else ''   # Dim (context, borders)
        # Modifiers
        self.RST   = '\033[0m'     if t else ''
        self.BLD   = '\033[1m'     if t else ''
        self.UND   = '\033[4m'     if t else ''
        self.INV   = '\033[7m'     if t else ''
        # Bright variants (for differentiation)
        self.BR    = '\033[1;31m'  if t else ''    # Bright red (CRIT)
        self.BG    = '\033[1;32m'  if t else ''    # Bright green (commands)
        self.BY    = '\033[1;33m'  if t else ''    # Bright yellow (HIGH)
        self.BC    = '\033[1;36m'  if t else ''    # Bright cyan (sections)
        # Backgrounds
        self.BG_R  = '\033[41m'    if t else ''
        self.BG_G  = '\033[42m'    if t else ''
        self.BG_Y  = '\033[43m'    if t else ''
        self.BG_B  = '\033[44m'    if t else ''
        self.BG_M  = '\033[45m'    if t else ''
        self.BG_C  = '\033[46m'    if t else ''
        self.BG_W  = '\033[47m'    if t else ''
        self.BG_D  = '\033[100m'   if t else ''
        # Long-name aliases (compatibility with tool-local class C)
        self.RED     = self.R
        self.GRN     = self.G
        self.YEL     = self.Y
        self.BLU     = self.B
        self.MAG     = self.M
        self.CYN     = self.C
        self.WHT     = self.W
        self.DIM     = self.D
        self.CRIT_BG = '\033[1;97;41m' if t else ''
        # Box-drawing characters (tools use C.HBAR etc.)
        self.HBAR    = '\u2500'
        self.VBAR    = '\u2502'
        self.TL      = '\u250c'
        self.TR      = '\u2510'
        self.BL      = '\u2514'
        self.BR      = '\u2518'
        self.TEE_R   = '\u251c'
        self.TEE_L   = '\u2524'
        self.CROSS   = '\u253c'
        self.ARROW   = '\u25b6'

C = Color()

# ── Box Drawing ─────────────────────────────────────────────────────────

BOX = {
    'tl': '╭', 'tr': '╮', 'bl': '╰', 'br': '╯',
    'h': '─', 'v': '│',
    'lt': '├', 'rt': '┤', 'tt': '┬', 'bt': '┴', 'x': '┼',
    'bullet': '●', 'arrow': '▸', 'check': '✓', 'cross': '✗',
    'warn': '⚠', 'bar_full': '█', 'bar_half': '▓', 'bar_empty': '░',
    'dot': '·', 'tri': '▶',
}

SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

# ── Severity Badges ─────────────────────────────────────────────────────
# Visual hierarchy: CRIT (inverse red BG, unmissable) > HIGH (bright yellow on dark)
# > WARN (yellow text) > MED (dim yellow) > LOW (blue) > INFO (cyan) > GOOD (green)

SEVERITY_BADGES = {
    'CRITICAL': (C.BG_R, C.W,   ' CRIT '),
    'CRIT':     (C.BG_R, C.W,   ' CRIT '),
    'HIGH':     (C.BG_Y, C.BLD, ' HIGH '),
    'WARNING':  (C.Y,    C.BLD, '[WARN]'),
    'WARN':     (C.Y,    C.BLD, '[WARN]'),
    'MEDIUM':   (C.Y,    '',    ' [MED]'),
    'MED':      (C.Y,    '',    ' [MED]'),
    'LOW':      (C.B,    '',    ' [LOW]'),
    'INFO':     (C.C,    '',    '[INFO]'),
    'GOOD':     (C.G,    '',    f'  [{BOX["check"]}] '),
}

def badge(severity):
    """Return a colored severity badge string."""
    sev = severity.upper()
    if sev in SEVERITY_BADGES:
        bg, fg, text = SEVERITY_BADGES[sev]
        return f"{bg}{fg}{text}{C.RST}"
    return f"[{sev}]"

# ── Spinner ─────────────────────────────────────────────────────────────

class Spinner:
    """Animated spinner for long-running operations."""
    def __init__(self, message="Working"):
        self.message = message
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self, final_message=None):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        sys.stdout.write(f"\r{' ' * 80}\r")
        sys.stdout.flush()
        if final_message:
            print(final_message)

    def update(self, message):
        self.message = message

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = SPINNER_FRAMES[i % len(SPINNER_FRAMES)]
            sys.stdout.write(f"\r  {C.BC}{frame}{C.RST} {C.W}{self.message}{C.RST}{' ' * 20}")
            sys.stdout.flush()
            i += 1
            self._stop.wait(0.08)

# ── Progress Bar ────────────────────────────────────────────────────────

def progress_bar(current, total, width=30, label="", show_eta=True, start_time=None):
    """Render a progress bar string."""
    if total <= 0:
        return ""
    pct = min(current / total, 1.0)
    filled = int(width * pct)
    empty = width - filled

    # Green when complete, cyan in progress, yellow at start
    bar_color = C.BG if pct >= 1.0 else C.C if pct > 0.3 else C.Y
    bar = f"{bar_color}{BOX['bar_full'] * filled}{C.D}{BOX['bar_empty'] * empty}{C.RST}"

    eta_str = ""
    if show_eta and start_time and current > 0 and pct < 1.0:
        elapsed = time.time() - start_time
        rate = current / elapsed if elapsed > 0 else 0
        remaining = (total - current) / rate if rate > 0 else 0
        if remaining < 60:
            eta_str = f" {C.D}ETA {remaining:.0f}s{C.RST}"
        else:
            eta_str = f" {C.D}ETA {remaining/60:.1f}m{C.RST}"

    pct_str = f"{C.W}{pct*100:>3.0f}%{C.RST}"
    counter = f"{C.D}{current}/{total}{C.RST}"
    return f"  {C.D}{BOX['v']}{C.RST} {bar} {pct_str} {counter}{eta_str} {label}"

# ── Table ───────────────────────────────────────────────────────────────

def table(headers, rows, max_col_width=40, indent=2):
    """Render a box-drawn table."""
    if not rows:
        return []

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = min(max(col_widths[i], len(str(cell))), max_col_width)

    pad = ' ' * indent
    sep_d = f"{C.D}{BOX['v']}{C.RST}"

    lines = []
    # Top border (dim, structural)
    segs = [BOX['h'] * (w + 2) for w in col_widths]
    lines.append(f"{pad}{C.D}{BOX['tl']}{BOX['tt'].join(segs)}{BOX['tr']}{C.RST}")

    # Header (white bold, the data that matters)
    cells = []
    for i, h in enumerate(headers):
        w = col_widths[i] if i < len(col_widths) else 10
        cells.append(f" {C.W}{h:<{w}}{C.RST} ")
    lines.append(f"{pad}{sep_d}{sep_d.join(cells)}{sep_d}")

    # Separator
    segs = [BOX['h'] * (w + 2) for w in col_widths]
    lines.append(f"{pad}{C.D}{BOX['lt']}{BOX['x'].join(segs)}{BOX['rt']}{C.RST}")

    # Rows (alternate subtle shading via content, keep borders dim)
    for row in rows:
        cells = []
        for i, cell in enumerate(row):
            w = col_widths[i] if i < len(col_widths) else 10
            s = str(cell)[:max_col_width]
            cells.append(f" {s:<{w}} ")
        lines.append(f"{pad}{sep_d}{sep_d.join(cells)}{sep_d}")

    # Bottom border
    segs = [BOX['h'] * (w + 2) for w in col_widths]
    lines.append(f"{pad}{C.D}{BOX['bl']}{BOX['bt'].join(segs)}{BOX['br']}{C.RST}")

    return lines

# ── Main UI Class ───────────────────────────────────────────────────────

class UI:
    """Main terminal UI controller for OSCP tools."""

    def __init__(self, title="TOOL", version="1.0", outfile=None, width=78):
        self.title = title
        self.version = version
        self.outfile = outfile
        self.width = width
        self.findings = []
        self.start_time = time.time()
        self._section_start = None
        self._task_count = 0
        self._task_total = 0
        self._lock = threading.Lock()

    # ── Core Output ────────────────────────────────────────────────

    def _write(self, msg=""):
        line = f"{msg}{C.RST}"
        with self._lock:
            print(line)
            if self.outfile:
                clean = re.sub(r'\033\[[0-9;]*m', '', line)
                self.outfile.write(clean + "\n")
                self.outfile.flush()

    # ── Banner ─────────────────────────────────────────────────────

    def banner(self, art_lines):
        """Print banner art. Accepts a list of pre-formatted strings."""
        for line in art_lines:
            self._write(line)
        self._write()

    # ── Sections ───────────────────────────────────────────────────
    #
    # Section = major phase (cyan box, bright, grabs attention)
    # Subsection = detail within a phase (magenta arrow, lighter)

    def section(self, title):
        """Major section header with box drawing."""
        elapsed = ""
        if self._section_start:
            dt = time.time() - self._section_start
            elapsed = f" {C.D}({dt:.1f}s)"
        self._section_start = time.time()

        self._write()
        w = self.width - 4
        self._write(f"  {C.D}{BOX['tl']}{BOX['h'] * w}{BOX['tr']}{C.RST}")
        elapsed_plain = re.sub(r'\033\[[0-9;]*m', '', elapsed)
        padding = max(0, w - len(title) - 5 - len(elapsed_plain))
        self._write(f"  {C.D}{BOX['v']}{C.RST}  {C.BC}{C.BLD}{BOX['arrow']} {title}{C.RST}{elapsed}{' ' * padding}{C.D}{BOX['v']}{C.RST}")
        self._write(f"  {C.D}{BOX['bl']}{BOX['h'] * w}{BOX['br']}{C.RST}")

    def subsection(self, title):
        """Minor section header."""
        self._write(f"\n  {C.M}{BOX['arrow']} {C.BLD}{title}{C.RST}")
        self._write(f"  {C.D}{BOX['h'] * (self.width - 4)}{C.RST}")

    # ── Findings ───────────────────────────────────────────────────
    #
    # Color rules:
    #   CRIT  = red inverse BG (unmissable)
    #   HIGH  = yellow BG (distinct from CRIT, still urgent)
    #   WARN  = yellow text
    #   INFO  = cyan bullet
    #   GOOD  = green check
    #   cmd   = GREEN (actionable, stands out from gray context)
    #   found = red arrows (exploit path, draws the eye)
    #   dim   = gray (background context)

    def finding(self, severity, category, message, exploit_cmd=""):
        """Log a finding with severity badge."""
        self.findings.append({
            "severity": severity.upper(),
            "category": category,
            "message": message,
            "exploit_cmd": exploit_cmd,
            "timestamp": datetime.now().isoformat(),
        })
        self._write(f"  {badge(severity)} {message}")

    def crit(self, msg):     self._write(f"  {badge('CRIT')} {msg}")
    def high(self, msg):     self._write(f"  {badge('HIGH')} {msg}")
    def warn(self, msg):     self._write(f"  {badge('WARN')} {msg}")
    def med(self, msg):      self._write(f"  {badge('MED')} {msg}")
    def low(self, msg):      self._write(f"  {badge('LOW')} {msg}")
    def info(self, msg):     self._write(f"  {C.C}{BOX['bullet']}{C.RST} {msg}")
    def good(self, msg):     self._write(f"  {C.BG}{BOX['check']}{C.RST} {msg}")
    def dim(self, msg):      self._write(f"    {C.D}{msg}{C.RST}")
    def found(self, msg):    self._write(f"  {C.BR}{BOX['tri']}{BOX['tri']}{BOX['tri']}{C.RST} {C.W}{msg}{C.RST}")

    def cmd(self, msg):
        """Exploit/action commands. GREEN so they pop against dim context."""
        self._write(f"    {C.BG}${C.RST} {C.G}{msg}{C.RST}")

    # ── Progress ───────────────────────────────────────────────────

    def set_total(self, total):
        """Set total task count for progress tracking."""
        self._task_total = total
        self._task_count = 0

    def step(self, label):
        """Advance progress by one step."""
        self._task_count += 1
        bar = progress_bar(
            self._task_count, self._task_total,
            width=25, label=label, start_time=self.start_time
        )
        self._write(bar)

    def progress(self, current, total, label=""):
        """Show a progress bar."""
        self._write(progress_bar(current, total, label=label, start_time=self.start_time))

    # ── Spinner Context ────────────────────────────────────────────

    @contextmanager
    def spinner(self, message="Working"):
        """Context manager that shows a spinner during long operations."""
        s = Spinner(message)
        s.start()
        try:
            yield s
        finally:
            s.stop()

    # ── Tables ─────────────────────────────────────────────────────

    def table(self, headers, rows, max_col_width=40):
        """Print a formatted table."""
        for line in table(headers, rows, max_col_width):
            self._write(line)

    # ── Summary Dashboard ──────────────────────────────────────────
    #
    # The summary box uses DIM borders so the colored data inside pops.
    # Severity labels use their own color. Counts are white bold.
    # Mini-bars use the severity color.

    def summary(self):
        """Print a summary dashboard of all findings."""
        elapsed = time.time() - self.start_time

        crits = [f for f in self.findings if f["severity"] in ("CRITICAL", "CRIT")]
        highs = [f for f in self.findings if f["severity"] == "HIGH"]
        warns = [f for f in self.findings if f["severity"] in ("WARNING", "WARN", "MEDIUM", "MED")]
        lows  = [f for f in self.findings if f["severity"] == "LOW"]
        infos = [f for f in self.findings if f["severity"] == "INFO"]

        self._write()
        w = self.width - 4

        # Box with dim borders, white bold title
        self._write(f"  {C.D}{BOX['tl']}{BOX['h'] * w}{BOX['tr']}{C.RST}")
        self._write(f"  {C.D}{BOX['v']}{C.RST}  {C.W}{C.BLD}FINDINGS SUMMARY{C.RST}{' ' * (w - 18)}{C.D}{BOX['v']}{C.RST}")
        self._write(f"  {C.D}{BOX['lt']}{BOX['h'] * w}{BOX['rt']}{C.RST}")

        # Severity rows: label in its color, count in white, bar in severity color
        total = len(self.findings) or 1
        for label, count, color in [
            ("CRITICAL", len(crits), C.BR),
            ("HIGH",     len(highs), C.BY),
            ("WARNING",  len(warns), C.Y),
            ("LOW",      len(lows),  C.B),
            ("INFO",     len(infos), C.C),
        ]:
            bar_len = int(20 * count / total) if count else 0
            bar = f"{color}{BOX['bar_full'] * bar_len}{C.D}{BOX['dot'] * (20 - bar_len)}{C.RST}"
            self._write(f"  {C.D}{BOX['v']}{C.RST}  {color}{label:<10}{C.RST} {C.W}{count:>3}{C.RST}  {bar}  {C.D}{BOX['v']}{C.RST}")

        self._write(f"  {C.D}{BOX['lt']}{BOX['h'] * w}{BOX['rt']}{C.RST}")

        # Elapsed time
        if elapsed < 60:
            time_str = f"{elapsed:.0f}s"
        else:
            time_str = f"{elapsed/60:.1f}m"
        self._write(f"  {C.D}{BOX['v']}{C.RST}  Completed in {C.W}{time_str}{C.RST}{' ' * (w - 18 - len(time_str))}{C.D}{BOX['v']}{C.RST}")
        self._write(f"  {C.D}{BOX['bl']}{BOX['h'] * w}{BOX['br']}{C.RST}")

        # Critical findings detail (red numbering, white data)
        if crits:
            self._write()
            self.subsection(f"Critical Findings ({len(crits)})")
            for i, f in enumerate(crits, 1):
                self._write(f"  {C.BR}{i}.{C.RST} {C.D}[{f['category']}]{C.RST} {C.W}{f['message']}{C.RST}")
                if f.get("exploit_cmd"):
                    self.cmd(f["exploit_cmd"])

        # High findings detail (yellow numbering)
        if highs:
            self._write()
            self.subsection(f"High Findings ({len(highs)})")
            for i, f in enumerate(highs, 1):
                self._write(f"  {C.BY}{i}.{C.RST} {C.D}[{f['category']}]{C.RST} {f['message']}")
                if f.get("exploit_cmd"):
                    self.cmd(f["exploit_cmd"])

    # ── JSON Export ────────────────────────────────────────────────

    def save_json(self, path):
        """Export findings as JSON."""
        data = {
            "tool": self.title,
            "version": self.version,
            "timestamp": datetime.now().isoformat(),
            "elapsed_seconds": round(time.time() - self.start_time, 1),
            "findings": self.findings,
            "summary": {
                "critical": len([f for f in self.findings if f["severity"] in ("CRITICAL", "CRIT")]),
                "high":     len([f for f in self.findings if f["severity"] == "HIGH"]),
                "warning":  len([f for f in self.findings if f["severity"] in ("WARNING", "WARN", "MEDIUM", "MED")]),
                "low":      len([f for f in self.findings if f["severity"] == "LOW"]),
                "info":     len([f for f in self.findings if f["severity"] == "INFO"]),
                "total":    len(self.findings),
            },
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    # ── Footer ─────────────────────────────────────────────────────

    def footer(self, tagline=""):
        """Print final footer with timing."""
        elapsed = time.time() - self.start_time
        crits = len([f for f in self.findings if f["severity"] in ("CRITICAL", "CRIT")])
        warns = len([f for f in self.findings if f["severity"] in ("WARNING", "WARN", "HIGH", "MEDIUM", "MED")])

        if elapsed < 60:
            time_str = f"{elapsed:.0f}s"
        else:
            time_str = f"{elapsed/60:.1f}m"

        self._write()
        w = self.width - 4
        self._write(f"  {C.D}{BOX['h'] * (w + 2)}{C.RST}")
        self._write(f"  {C.BG}{C.BLD}{self.title} v{self.version}{C.RST} complete. "
                     f"{C.D}{time_str}{C.RST}  "
                     f"{C.BR}{crits} critical{C.RST}  "
                     f"{C.BY}{warns} warnings{C.RST}")
        if tagline:
            self._write(f"  {C.D}{tagline}{C.RST}")
        self._write()


# ── Standalone test ─────────────────────────────────────────────────────

if __name__ == "__main__":
    ui = UI(title="TUI Demo", version="1.0.0")
    ui.section("DEMO OUTPUT")
    ui.info("This is an info message")
    ui.good("This check passed")
    ui.crit("This is a critical finding")
    ui.high("This is a high finding")
    ui.warn("This is a warning")
    ui.med("This is a medium")
    ui.low("This is a low")
    ui.cmd("nmap -sCV -p- 10.10.10.5")
    ui.found("Anonymous FTP login allowed!")
    ui.dim("This is dim context text")

    ui.subsection("Progress Bar Demo")
    ui.set_total(5)
    for i in range(5):
        ui.step(f"Check {i+1}")
        time.sleep(0.1)

    ui.subsection("Table Demo")
    ui.table(
        ["Port", "Service", "Version"],
        [
            ["22/tcp", "ssh", "OpenSSH 8.2"],
            ["80/tcp", "http", "Apache 2.4.41"],
            ["443/tcp", "https", "nginx 1.18"],
        ]
    )

    ui.finding("CRITICAL", "FTP", "Anonymous login allowed", "ftp 10.10.10.5")
    ui.finding("HIGH", "SMB", "Null session permitted", "smbclient -L //target -N")
    ui.finding("WARNING", "HTTP", "Directory listing enabled")
    ui.finding("INFO", "SSH", "Password auth enabled")

    ui.summary()
    ui.footer("TUI finds paths. You walk them.")
