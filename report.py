"""
Cantina HTML report generator.

Pure-Python, deterministic, no AI, no network calls. OSCP-exam safe.

Builds a single self-contained HTML file (inline CSS + minimal vanilla JS) from
a finished Scanner instance and the on-disk output directories. The report is
designed to be:

  - Easy to read in a browser (dark theme, severity colors, collapsibles)
  - Easy to print (forced light theme + page breaks via @media print)
  - Easy to copy-paste into an OSCP exam report (Markdown blocks at the bottom
    cover ports, tools used, methodology timeline, and findings)

Public entry point:
    build_html_report(scanner, outdir, args, start_time, end_time) -> Path
"""

from __future__ import annotations

import html
import os
import time
from pathlib import Path

REPORT_FILENAME = "report.html"
MAX_EMBED_LINES = 800   # truncate embedded files past this; show head+tail
MAX_EMBED_BYTES = 512 * 1024


# ── helpers ─────────────────────────────────────────────────────────────────

def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in str(s).lower()).strip("-")


def _read_file(path: Path, max_lines: int = MAX_EMBED_LINES,
               max_bytes: int = MAX_EMBED_BYTES) -> tuple[str, int, bool]:
    """Read a file safely. Returns (content, total_lines, was_truncated)."""
    try:
        size = path.stat().st_size
        if size > max_bytes:
            with open(path, "r", errors="replace") as f:
                head = f.read(max_bytes // 2)
            try:
                with open(path, "rb") as f:
                    f.seek(-max_bytes // 2, os.SEEK_END)
                    tail = f.read().decode("utf-8", errors="replace")
            except Exception:
                tail = ""
            content = (
                head
                + f"\n\n... [truncated: file is {size} bytes, showing head+tail] ...\n\n"
                + tail
            )
            return content, content.count("\n"), True

        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
        if len(lines) > max_lines:
            half = max_lines // 2
            kept = (
                lines[:half]
                + [f"\n... [truncated {len(lines) - max_lines} lines] ...\n\n"]
                + lines[-half:]
            )
            return "".join(kept), len(lines), True
        return "".join(lines), len(lines), False
    except Exception as e:
        return f"[Could not read {path.name}: {e}]", 0, False


def _badge(severity: str) -> str:
    s = (severity or "INFO").upper()
    return f'<span class="badge sev-{_slug(s)}">{_esc(s)}</span>'


def _human_dur(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# ── inline assets ───────────────────────────────────────────────────────────

CSS = r"""
:root {
  --bg: #0d1117;
  --bg2: #161b22;
  --bg3: #1f262e;
  --fg: #e6edf3;
  --fg2: #8b949e;
  --line: #30363d;
  --accent: #58a6ff;
  --crit: #f85149;
  --warn: #d29922;
  --good: #56d364;
  --info: #58a6ff;
  --code: #c9d1d9;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: -apple-system, "Segoe UI", "Helvetica Neue", system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.55;
  color: var(--fg);
  background: var(--bg);
}
main { max-width: 1180px; margin: 0 auto; padding: 24px 32px 80px; }
header.report-head {
  border-bottom: 1px solid var(--line);
  padding-bottom: 18px;
  margin-bottom: 22px;
}
header.report-head h1 {
  margin: 0 0 6px;
  font-size: 28px;
  letter-spacing: 0.5px;
}
header.report-head .meta {
  color: var(--fg2);
  font-size: 13px;
}
header.report-head .meta span { margin-right: 18px; }
header.report-head .meta b { color: var(--fg); font-weight: 600; }

nav.toc {
  background: var(--bg2);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 14px 20px;
  margin: 0 0 28px;
  font-size: 13px;
}
nav.toc ol { margin: 0; padding-left: 22px; }
nav.toc li { margin: 2px 0; }
nav.toc a { color: var(--accent); text-decoration: none; }
nav.toc a:hover { text-decoration: underline; }

section { margin: 28px 0; }
section > h2 {
  font-size: 20px;
  margin: 0 0 12px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--line);
}
section > h3 {
  font-size: 15px;
  margin: 18px 0 8px;
  color: var(--fg2);
  text-transform: uppercase;
  letter-spacing: 0.6px;
}

.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
  margin: 14px 0;
}
.card {
  background: var(--bg2);
  border: 1px solid var(--line);
  border-left: 3px solid var(--accent);
  border-radius: 6px;
  padding: 12px 16px;
}
.card .label { color: var(--fg2); font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; }
.card .value { font-size: 24px; font-weight: 600; margin-top: 4px; }
.card.crit { border-left-color: var(--crit); }
.card.warn { border-left-color: var(--warn); }
.card.good { border-left-color: var(--good); }

table {
  width: 100%;
  border-collapse: collapse;
  background: var(--bg2);
  margin: 10px 0;
  font-size: 13px;
}
table th, table td {
  text-align: left;
  padding: 8px 12px;
  border-bottom: 1px solid var(--line);
}
table th {
  background: var(--bg3);
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.6px;
  color: var(--fg2);
}
table td.num { font-variant-numeric: tabular-nums; }

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.6px;
}
.sev-critical { background: rgba(248, 81, 73, 0.15); color: var(--crit); border: 1px solid var(--crit); }
.sev-warning  { background: rgba(210, 153, 34, 0.15); color: var(--warn); border: 1px solid var(--warn); }
.sev-info     { background: rgba(88, 166, 255, 0.15); color: var(--info); border: 1px solid var(--info); }
.sev-good     { background: rgba(86, 211, 100, 0.15); color: var(--good); border: 1px solid var(--good); }

.finding {
  background: var(--bg2);
  border: 1px solid var(--line);
  border-left: 3px solid var(--info);
  border-radius: 4px;
  padding: 12px 16px;
  margin: 10px 0;
}
.finding.sev-critical { border-left-color: var(--crit); }
.finding.sev-warning  { border-left-color: var(--warn); }
.finding.sev-info     { border-left-color: var(--info); }
.finding .cat { color: var(--fg2); font-weight: 600; margin-left: 8px; }
.finding .msg { display: block; margin-top: 6px; }

pre, code {
  font-family: "JetBrains Mono", Menlo, Consolas, monospace;
  font-size: 12.5px;
}
pre {
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 12px 14px;
  overflow-x: auto;
  margin: 8px 0;
  color: var(--code);
  position: relative;
}
code.inline {
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 1px 6px;
}
.copy-btn {
  position: absolute;
  top: 6px;
  right: 6px;
  background: var(--bg3);
  color: var(--fg2);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 2px 8px;
  font-size: 11px;
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.15s;
}
pre:hover .copy-btn, .copy-btn:focus { opacity: 1; }
.copy-btn:hover { background: var(--bg2); color: var(--fg); }
.copy-btn.copied { color: var(--good); border-color: var(--good); opacity: 1; }

details {
  margin: 8px 0;
  background: var(--bg2);
  border: 1px solid var(--line);
  border-radius: 4px;
}
details > summary {
  cursor: pointer;
  padding: 8px 14px;
  font-weight: 600;
  list-style: none;
  position: relative;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: "▸";
  display: inline-block;
  margin-right: 8px;
  transition: transform 0.15s;
  color: var(--fg2);
}
details[open] > summary::before { transform: rotate(90deg); }
details > summary .meta { color: var(--fg2); font-weight: 400; margin-left: 10px; font-size: 12px; }
details > pre { margin: 0; border-radius: 0 0 4px 4px; border: none; border-top: 1px solid var(--line); }

.cmd-row {
  display: grid;
  grid-template-columns: 60px 80px 1fr 90px 60px;
  gap: 8px;
  align-items: center;
  padding: 6px 0;
  border-bottom: 1px solid var(--line);
  font-size: 12.5px;
}
.cmd-row:last-child { border-bottom: none; }
.cmd-row .num { color: var(--fg2); font-variant-numeric: tabular-nums; }
.cmd-row .ts  { color: var(--fg2); font-family: "JetBrains Mono", Menlo, monospace; }
.cmd-row .cmd { font-family: "JetBrains Mono", Menlo, monospace; word-break: break-all; }
.cmd-row .dur { color: var(--fg2); text-align: right; font-variant-numeric: tabular-nums; }
.cmd-row .rc.ok   { color: var(--good); }
.cmd-row .rc.fail { color: var(--crit); }

.muted { color: var(--fg2); font-style: italic; }
.note  { background: var(--bg2); border-left: 3px solid var(--accent); padding: 10px 14px; margin: 12px 0; }

.toolbar {
  display: flex;
  gap: 8px;
  margin: 0 0 18px;
  flex-wrap: wrap;
}
.toolbar button {
  background: var(--bg2);
  color: var(--fg);
  border: 1px solid var(--line);
  border-radius: 4px;
  padding: 5px 12px;
  font-size: 12px;
  cursor: pointer;
}
.toolbar button:hover { background: var(--bg3); }
.toolbar button.active { background: var(--accent); color: #000; border-color: var(--accent); }

footer.report-foot {
  margin-top: 60px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  color: var(--fg2);
  font-size: 12px;
  text-align: center;
}

/* Print mode: light theme, expand all details, hide buttons */
@media print {
  :root {
    --bg: #ffffff; --bg2: #f6f8fa; --bg3: #eaeef2;
    --fg: #1f2328; --fg2: #57606a; --line: #d0d7de;
    --code: #1f2328;
  }
  body { background: #fff; color: #1f2328; }
  main { max-width: none; padding: 0; }
  details { page-break-inside: avoid; }
  details > summary::before { content: ""; }
  details:not([open]) > summary + * { display: block !important; }
  details > summary + * { display: block !important; }
  .copy-btn, .toolbar { display: none !important; }
  pre { white-space: pre-wrap; word-break: break-all; border: 1px solid #d0d7de; }
  section { page-break-inside: avoid; }
  section > h2 { page-break-after: avoid; }
  .finding { page-break-inside: avoid; }
  nav.toc { display: none; }
}
"""

JS = r"""
(function () {
  // Add copy buttons to every pre
  document.querySelectorAll('pre').forEach(function (pre) {
    if (pre.querySelector('.copy-btn')) return;
    var btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.type = 'button';
    btn.textContent = 'Copy';
    btn.addEventListener('click', function () {
      var code = pre.querySelector('code');
      var text = code ? code.textContent : pre.textContent;
      // Strip the button label out of pre.textContent
      text = text.replace(/^Copy\s*/, '');
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = 'Copied';
        btn.classList.add('copied');
        setTimeout(function () {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 1500);
      }, function () {
        btn.textContent = 'Failed';
        setTimeout(function () { btn.textContent = 'Copy'; }, 1500);
      });
    });
    pre.appendChild(btn);
  });

  // Expand-all / collapse-all controls
  var expand = document.getElementById('btn-expand');
  var collapse = document.getElementById('btn-collapse');
  if (expand) expand.addEventListener('click', function () {
    document.querySelectorAll('details').forEach(function (d) { d.open = true; });
  });
  if (collapse) collapse.addEventListener('click', function () {
    document.querySelectorAll('details').forEach(function (d) { d.open = false; });
  });

  // Severity filter
  document.querySelectorAll('.sev-filter').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var sev = btn.dataset.sev;
      var allBtns = document.querySelectorAll('.sev-filter');
      allBtns.forEach(function (b) { b.classList.toggle('active', b === btn); });
      document.querySelectorAll('.finding').forEach(function (f) {
        if (sev === 'all') { f.style.display = ''; return; }
        f.style.display = f.classList.contains('sev-' + sev) ? '' : 'none';
      });
    });
  });
})();
"""


# ── section renderers ───────────────────────────────────────────────────────

def _render_header(target, scan_type, started_at, ended_at, duration, os_guess,
                   tunnel_info, version) -> str:
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started_at))
    ended = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ended_at))
    return f"""
<header class="report-head">
  <h1>Cantina Recon Report</h1>
  <div class="meta">
    <span>Target: <b>{_esc(target)}</b></span>
    <span>Scan type: <b>{_esc(scan_type)}</b></span>
    <span>OS guess: <b>{_esc(os_guess)}</b></span>
    {f'<span>Pivot: <b>{_esc(tunnel_info)}</b></span>' if tunnel_info else ''}
  </div>
  <div class="meta">
    <span>Started: <b>{started}</b></span>
    <span>Ended: <b>{ended}</b></span>
    <span>Duration: <b>{_human_dur(duration)}</b></span>
    <span>Cantina: <b>v{_esc(version)}</b></span>
  </div>
</header>
<div class="toolbar">
  <button id="btn-expand" type="button">Expand all</button>
  <button id="btn-collapse" type="button">Collapse all</button>
  <button onclick="window.print()" type="button">Print / Save as PDF</button>
</div>
"""


def _render_toc(sections: list[tuple[str, str]]) -> str:
    items = "\n".join(
        f'<li><a href="#{sid}">{_esc(label)}</a></li>'
        for sid, label in sections
    )
    return f'<nav class="toc"><ol>{items}</ol></nav>'


def _render_summary(scanner) -> str:
    crit = sum(1 for f in scanner.findings if f.get("severity") == "CRITICAL")
    warn = sum(1 for f in scanner.findings if f.get("severity") == "WARNING")
    info = sum(1 for f in scanner.findings if f.get("severity") == "INFO")
    cmd_count = len(getattr(scanner, "cmd_log", []))
    return f"""
<section id="summary">
  <h2>Executive Summary</h2>
  <div class="card-grid">
    <div class="card"><div class="label">Open TCP ports</div><div class="value">{len(scanner.tcp_ports)}</div></div>
    <div class="card"><div class="label">Open UDP ports</div><div class="value">{len(scanner.udp_ports)}</div></div>
    <div class="card crit"><div class="label">Critical findings</div><div class="value">{crit}</div></div>
    <div class="card warn"><div class="label">Warning findings</div><div class="value">{warn}</div></div>
    <div class="card good"><div class="label">Info findings</div><div class="value">{info}</div></div>
    <div class="card"><div class="label">Commands run</div><div class="value">{cmd_count}</div></div>
  </div>
</section>
"""


def _render_ports_section(scanner) -> str:
    def table(title, ports):
        if not ports:
            return f'<h3>{_esc(title)}</h3><p class="muted">No {title.lower()} ports discovered.</p>'
        rows = "\n".join(
            f'<tr><td class="num">{p["port"]}</td><td>{_esc(p["proto"])}</td>'
            f'<td>{_esc(p["service"])}</td><td>{_esc(p["version"])}</td></tr>'
            for p in sorted(ports.values(), key=lambda x: x["port"])
        )
        return (
            f'<h3>{_esc(title)}</h3>'
            f'<table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )

    return f"""
<section id="ports">
  <h2>Open Ports &amp; Services</h2>
  {table("TCP", scanner.tcp_ports)}
  {table("UDP", scanner.udp_ports)}
</section>
"""


def _render_findings_section(findings) -> str:
    if not findings:
        body = '<p class="muted">No findings recorded.</p>'
    else:
        cards = []
        for i, f in enumerate(findings):
            sev = (f.get("severity") or "INFO").upper()
            cat = f.get("category", "")
            msg = f.get("message", "")
            cmd = f.get("exploit_cmd") or ""
            cmd_html = ""
            if cmd:
                cmd_html = f'<pre><code>{_esc(cmd)}</code></pre>'
            cards.append(
                f'<div class="finding sev-{_slug(sev)}">'
                f'{_badge(sev)}<span class="cat">{_esc(cat)}</span>'
                f'<span class="msg">{_esc(msg)}</span>'
                f'{cmd_html}'
                f'</div>'
            )
        body = "\n".join(cards)

    return f"""
<section id="findings">
  <h2>Findings</h2>
  <div class="toolbar">
    <button class="sev-filter active" data-sev="all" type="button">All</button>
    <button class="sev-filter" data-sev="critical" type="button">Critical</button>
    <button class="sev-filter" data-sev="warning" type="button">Warning</button>
    <button class="sev-filter" data-sev="info" type="button">Info</button>
  </div>
  {body}
</section>
"""


def _render_commands_section(cmd_log: list[dict], session_start: float) -> str:
    if not cmd_log:
        return """
<section id="commands">
  <h2>Commands Executed</h2>
  <p class="muted">No commands were tracked. (Service-recon raw outputs are still embedded below; tracked commands come from nmap, custom toolkit dispatch, and proxychains-wrapped recon.)</p>
</section>
"""
    rows = []
    for i, c in enumerate(cmd_log, 1):
        ts = time.strftime("%H:%M:%S", time.localtime(c["started"]))
        elapsed = c["started"] - session_start
        rc = c.get("rc", 0)
        rc_class = "ok" if rc == 0 else "fail"
        rows.append(
            f'<div class="cmd-row">'
            f'<span class="num">{i:03d}</span>'
            f'<span class="ts">+{int(elapsed):>4d}s</span>'
            f'<span class="cmd">{_esc(c["cmd"])}</span>'
            f'<span class="dur">{c.get("duration", 0):.1f}s</span>'
            f'<span class="rc {rc_class}">{rc}</span>'
            f'</div>'
        )
    return f"""
<section id="commands">
  <h2>Commands Executed</h2>
  <p class="muted">Chronological log of tracked commands (nmap scans, custom-toolkit dispatch, proxychains-wrapped recon). Raw service-recon outputs are embedded below.</p>
  <div class="cmd-row" style="font-weight:600;color:var(--fg2);text-transform:uppercase;letter-spacing:0.6px;font-size:11px;">
    <span class="num">#</span><span class="ts">+T</span><span class="cmd">Command</span><span class="dur">Dur</span><span class="rc">RC</span>
  </div>
  {"".join(rows)}
</section>
"""


def _render_files_section(section_id: str, title: str, files: list[Path],
                          intro: str = "") -> str:
    if not files:
        return ""
    blocks = []
    for f in sorted(files):
        content, total_lines, truncated = _read_file(f)
        meta = f"{total_lines} lines"
        if truncated:
            meta += " · truncated"
        blocks.append(
            f'<details>'
            f'<summary>{_esc(f.name)}<span class="meta">{meta}</span></summary>'
            f'<pre><code>{_esc(content)}</code></pre>'
            f'</details>'
        )
    intro_html = f'<p class="muted">{_esc(intro)}</p>' if intro else ""
    return f"""
<section id="{section_id}">
  <h2>{_esc(title)}</h2>
  {intro_html}
  {"".join(blocks)}
</section>
"""


def _md_escape(s: str) -> str:
    """Minimal markdown-pipe escaping for table cells."""
    return str(s).replace("|", "\\|").replace("\n", " ")


def _render_report_blocks(scanner, scan_type: str) -> str:
    """Markdown-formatted blocks for direct copy-paste into the OSCP report."""
    target = scanner.target

    # Ports table (markdown)
    ports = []
    all_ports = sorted(
        list(scanner.tcp_ports.values()) + list(scanner.udp_ports.values()),
        key=lambda x: (x["proto"], x["port"]),
    )
    if all_ports:
        ports.append("| Port | Proto | Service | Version |")
        ports.append("|------|-------|---------|---------|")
        for p in all_ports:
            ports.append(
                f"| {p['port']} | {p['proto']} | "
                f"{_md_escape(p['service'])} | {_md_escape(p['version'])} |"
            )
    ports_md = "\n".join(ports) if ports else "_No ports discovered._"

    # Tools-used (deduped from cmd_log)
    tools_seen = []
    seen = set()
    for c in getattr(scanner, "cmd_log", []):
        tool = (c.get("cmd", "").split() or [""])[0]
        # strip leading proxychains
        if tool == "proxychains" and len(c["cmd"].split()) > 1:
            parts = c["cmd"].split()
            # skip proxychains and any -q/-f flags
            j = 1
            while j < len(parts) and parts[j].startswith("-"):
                j += 1
            tool = parts[j] if j < len(parts) else "proxychains"
        tool = os.path.basename(tool)
        if tool and tool not in seen:
            seen.add(tool)
            tools_seen.append(tool)
    tools_md = (
        "\n".join(f"- `{t}`" for t in tools_seen) if tools_seen else "_No tools tracked._"
    )

    # Methodology (numbered, chronological)
    method_lines = []
    for i, c in enumerate(getattr(scanner, "cmd_log", []), 1):
        cmd = c.get("cmd", "")
        label = c.get("label", "")
        if label:
            method_lines.append(f"{i}. **{_md_escape(label)}**\n    ```\n    {cmd}\n    ```")
        else:
            method_lines.append(f"{i}. ```\n    {cmd}\n    ```")
    method_md = "\n".join(method_lines) if method_lines else "_No commands tracked._"

    # Findings as markdown
    f_lines = []
    for f in scanner.findings:
        sev = f.get("severity", "INFO")
        cat = f.get("category", "")
        msg = f.get("message", "")
        cmd = f.get("exploit_cmd") or ""
        f_lines.append(f"### {sev} — {cat}")
        f_lines.append(msg)
        if cmd:
            f_lines.append("```")
            f_lines.append(cmd)
            f_lines.append("```")
        f_lines.append("")
    findings_md = "\n".join(f_lines) if f_lines else "_No findings recorded._"

    full_md = f"""## {target} — Service Enumeration

**Scan type:** {scan_type}

### Open Ports

{ports_md}

### Tools Used

{tools_md}

### Methodology

{method_md}

### Findings

{findings_md}
"""
    return f"""
<section id="report-blocks">
  <h2>Report-Ready Markdown</h2>
  <p class="muted">Drop these blocks straight into your OSCP exam report. They include the port table, tools-used list, chronological methodology, and findings, all rendered as Markdown.</p>
  <details open>
    <summary>Combined Markdown <span class="meta">copy → paste into report</span></summary>
    <pre><code>{_esc(full_md)}</code></pre>
  </details>
</section>
"""


def _render_session_log(session_log: Path) -> str:
    if not session_log.exists():
        return ""
    content, total_lines, truncated = _read_file(session_log)
    meta = f"{total_lines} lines"
    if truncated:
        meta += " · truncated"
    return f"""
<section id="session-log">
  <h2>Raw Session Log</h2>
  <details>
    <summary>{_esc(session_log.name)}<span class="meta">{meta}</span></summary>
    <pre><code>{_esc(content)}</code></pre>
  </details>
</section>
"""


# ── public entry point ──────────────────────────────────────────────────────

def build_html_report(scanner, outdir, args, start_time: float,
                       end_time: float | None = None) -> Path:
    """
    Build a self-contained HTML report from a finished Scanner instance.

    Args:
        scanner: a Cantina Scanner instance after scans have run
        outdir:  per-target output directory (Path or str)
        args:    argparse Namespace from cantina.main (uses .type, .target)
        start_time: time.time() when scanning started
        end_time:   time.time() when scanning ended (defaults to now)

    Returns:
        Path to the generated HTML report.
    """
    if end_time is None:
        end_time = time.time()
    outdir = Path(outdir)
    nmap_dir = outdir / "nmap"
    recon_dir = outdir / "recon"

    nmap_files = sorted(nmap_dir.glob("*")) if nmap_dir.exists() else []
    nmap_files = [f for f in nmap_files if f.is_file()]
    recon_files = sorted(recon_dir.glob("*")) if recon_dir.exists() else []
    recon_files = [f for f in recon_files if f.is_file()]
    session_log = outdir / "cantina.log"

    # Tunnel info, if any
    tunnel_info = ""
    tctx = getattr(scanner, "_tctx", None)
    if tctx and getattr(tctx, "tunneled", False):
        tunnel_info = f"{getattr(tctx, 'interface', '?')} ({getattr(tctx, 'subnet', '?')})"

    # Try to get cantina version (lazy import to avoid circular deps)
    try:
        from cantina import VERSION as _v
        version = _v
    except Exception:
        version = "1.0.0"

    sections: list[tuple[str, str]] = []
    sections.append(("summary", "Executive Summary"))
    sections.append(("ports", "Open Ports & Services"))
    sections.append(("findings", "Findings"))
    sections.append(("commands", "Commands Executed"))
    if nmap_files:
        sections.append(("nmap-output", "Nmap Outputs"))
    if recon_files:
        sections.append(("recon-output", "Service Recon Outputs"))
    sections.append(("report-blocks", "Report-Ready Markdown"))
    if session_log.exists():
        sections.append(("session-log", "Raw Session Log"))

    parts: list[str] = []
    parts.append(_render_header(
        target=scanner.target,
        scan_type=getattr(args, "type", "?"),
        started_at=start_time,
        ended_at=end_time,
        duration=end_time - start_time,
        os_guess=getattr(scanner, "os_guess", "unknown"),
        tunnel_info=tunnel_info,
        version=version,
    ))
    parts.append(_render_toc(sections))
    parts.append(_render_summary(scanner))
    parts.append(_render_ports_section(scanner))
    parts.append(_render_findings_section(scanner.findings))
    parts.append(_render_commands_section(getattr(scanner, "cmd_log", []), start_time))
    parts.append(_render_files_section(
        "nmap-output", "Nmap Outputs", nmap_files,
        intro="Raw nmap output files. Each block is the unmodified -oN text saved by cantina."
    ))
    parts.append(_render_files_section(
        "recon-output", "Service Recon Outputs", recon_files,
        intro="Raw output from service-specific recon tools (feroxbuster, nikto, smbmap, enum4linux, custom toolkit, etc.)."
    ))
    parts.append(_render_report_blocks(scanner, getattr(args, "type", "?")))
    parts.append(_render_session_log(session_log))
    parts.append(
        '<footer class="report-foot">Generated by Cantina · '
        f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_time))} · '
        'Deterministic HTML report, no AI used.</footer>'
    )

    body = "\n".join(parts)

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cantina Report — {_esc(scanner.target)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
{body}
</main>
<script>{JS}</script>
</body>
</html>
"""

    out_path = outdir / REPORT_FILENAME
    out_path.write_text(full_html, encoding="utf-8")
    return out_path
