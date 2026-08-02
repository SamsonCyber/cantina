"""
Tests for cantina.py - Network recon orchestrator.
Covers: target validation (shipped function), nmap XML/normal parse,
        load_scan_ports merge optimization, scorecard, Scanner helpers.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "cantina_bench"


# ── Target Validation (shipped validate_target) ─────────────────────────

class TestTargetValidation:
    def test_source_exports_validate_target(self):
        from cantina import validate_target
        assert callable(validate_target)

    def test_main_uses_validate_target(self):
        import inspect
        import cantina
        source = inspect.getsource(cantina.main)
        assert "validate_target" in source

    @pytest.mark.parametrize("target", [
        "10.10.10.1", "10.10.10.0/24", "target.htb",
        "admin.target.htb", "my-target.htb", "127.0.0.1",
    ])
    def test_valid_targets(self, target):
        from cantina import validate_target
        assert validate_target(target) is True

    @pytest.mark.parametrize("target,desc", [
        ("10.10.10.1; rm -rf /", "semicolon"),
        ("10.10.10.1`id`", "backtick"),
        ("$(whoami)", "dollar subshell"),
        ("10.10.10.1 | cat /etc/passwd", "pipe"),
        ("10.10.10.1 && id", "ampersand"),
        ("10.10.10.1 -oG /tmp/pwn", "nmap flag injection"),
        ("", "empty string"),
        ("../../etc/passwd", "path traversal"),
    ])
    def test_injection_blocked(self, target, desc):
        from cantina import validate_target
        assert validate_target(target) is False, f"Should block: {desc}"


# ── Nmap parsing (real shipped functions) ───────────────────────────────

class TestNmapParsing:
    def test_parse_normal_fixture_ports(self):
        from cantina import parse_nmap_normal_ports
        ports = parse_nmap_normal_ports(FIXTURE_DIR / "quick.nmap")
        assert set(ports) == {22, 80, 445, 3306}
        assert ports[22]["service"] == "ssh"
        assert "OpenSSH" in ports[22]["version"]
        assert ports[3306]["service"] == "unknown"

    def test_parse_xml_fixture_enriches_and_extends(self):
        from cantina import parse_nmap_xml_ports
        ports = parse_nmap_xml_ports(FIXTURE_DIR / "quick.xml")
        assert set(ports) == {22, 80, 445, 3306, 8080}
        assert ports[3306]["service"] == "mysql"
        assert "5.7" in ports[3306]["version"]
        assert ports[8080]["service"] == "http-proxy"

    def test_parse_nmap_ports_auto_xml(self):
        from cantina import parse_nmap_ports
        ports = parse_nmap_ports(FIXTURE_DIR / "quick.xml")
        assert 8080 in ports
        assert ports[80]["service"] == "http"

    def test_load_scan_ports_merges_sibling_xml(self):
        """Optimization: sparse .nmap + sibling .xml → richer ports."""
        from cantina import load_scan_ports, parse_nmap_normal_ports
        legacy = parse_nmap_normal_ports(FIXTURE_DIR / "quick.nmap")
        merged = load_scan_ports(FIXTURE_DIR / "quick.nmap")
        assert len(merged) > len(legacy)  # XML adds 8080
        assert merged[3306]["service"] == "mysql"  # unknown upgraded
        assert "MySQL" in merged[3306]["version"] or "5.7" in merged[3306]["version"]

    def test_merge_port_dicts_prefers_richer(self):
        from cantina import merge_port_dicts, _port_record
        a = {80: _port_record(80, "tcp", "unknown", "")}
        b = {80: _port_record(80, "tcp", "http", "Apache 2.4")}
        m = merge_port_dicts(a, b)
        assert m[80]["service"] == "http"
        assert "Apache" in m[80]["version"]


# ── Jedi findings ───────────────────────────────────────────────────────

class TestJediFindings:
    def test_parse_jedi_findings_from_fixture(self, tmp_path):
        from cantina import Scanner
        sc = Scanner("10.10.10.50", str(tmp_path), rate=4, resume=False)
        sc.findings = []
        sc.parse_jedi_findings(FIXTURE_DIR / "quick.nmap")
        sevs = {f["severity"] for f in sc.findings}
        assert "LOW" in sevs
        assert "WARNING" in sevs
        assert "CRITICAL" in sevs
        # INFO tags skipped
        assert "INFO" not in sevs


# ── Scanner Class ───────────────────────────────────────────────────────

class TestScannerInit:
    def test_scanner_exists(self):
        from cantina import Scanner
        assert callable(Scanner)

    def test_scanner_stores_target(self, tmp_path):
        from cantina import Scanner
        s = Scanner("10.10.10.1", str(tmp_path), rate=4, resume=False)
        assert s.target == "10.10.10.1"

    def test_nmap_dual_writes_xml_flag(self):
        """_nmap command string must dual-write -oN and -oX (OSCP-legal enum only)."""
        import inspect
        from cantina import Scanner
        src = inspect.getsource(Scanner._nmap)
        assert "-oN" in src and "-oX" in src


# ── Scorecard ───────────────────────────────────────────────────────────

class TestCantinaScore:
    def test_score_ports_metrics(self):
        from cantina import load_scan_ports
        from cantina_score import score_ports
        ports = load_scan_ports(FIXTURE_DIR / "quick.nmap")
        s = score_ports(ports)
        assert s["ports_found"] == 5
        assert s["services_named"] >= 4
        assert s["versions_filled"] >= 3
        assert 0 <= s["completeness"] <= 100

    def test_optimized_beats_legacy_completeness(self):
        from cantina import load_scan_ports, parse_nmap_normal_ports
        from cantina_score import score_scan
        legacy = score_scan(parse_nmap_normal_ports(FIXTURE_DIR / "quick.nmap"), mode="legacy")
        opt = score_scan(load_scan_ports(FIXTURE_DIR / "quick.nmap"), mode="optimized")
        assert opt["metrics"]["ports_found"] > legacy["metrics"]["ports_found"]
        assert opt["metrics"]["completeness"] > legacy["metrics"]["completeness"]

    def test_compare_scores_verdicts(self):
        from cantina_score import compare_scores, score_scan
        a = score_scan({22: {"port": 22, "proto": "tcp", "service": "ssh", "version": ""}}, label="a")
        b = score_scan(
            {
                22: {"port": 22, "proto": "tcp", "service": "ssh", "version": "8.9"},
                80: {"port": 80, "proto": "tcp", "service": "http", "version": "1.1"},
            },
            label="b",
        )
        d = compare_scores(a, b)
        assert d["metrics"]["ports_found"]["verdict"] == "improve"
        assert d["metrics"]["ports_found"]["delta"] == 1.0

    def test_compare_flat_reproducible(self):
        from cantina import load_scan_ports
        from cantina_score import compare_scores, score_scan
        ports = load_scan_ports(FIXTURE_DIR / "quick.nmap")
        s1 = score_scan(ports, label="r1")
        s2 = score_scan(ports, label="r2")
        d = compare_scores(s1, s2)
        for row in d["metrics"].values():
            assert row["verdict"] == "flat"


# ── Benchmark entry point ───────────────────────────────────────────────

class TestCantinaBench:
    def test_run_benchmark_twice_writes_artifacts(self, tmp_path):
        from cantina_bench import run_benchmark
        result = run_benchmark(FIXTURE_DIR, tmp_path, twice=True)
        assert (tmp_path / "cantina_bench_run1.json").exists()
        assert (tmp_path / "cantina_bench_run2.json").exists()
        assert (tmp_path / "cantina_bench_delta.txt").exists()
        # Optimized must improve vs legacy on ports_found (XML adds 8080)
        assert result["delta_legacy_vs_opt"]["metrics"]["ports_found"]["verdict"] == "improve"
        # Consecutive optimized runs flat
        assert result["delta_run1_vs_run2"]["metrics"]["composite"]["verdict"] == "flat"

    def test_module_doc_oscp_legal(self):
        import cantina
        assert "Enumeration only" in cantina.__doc__
        assert "No exploitation" in cantina.__doc__
        assert "OSCP" in cantina.__doc__


# ── Deep / background status ────────────────────────────────────────────

class TestDeepMode:
    def test_deep_in_scan_choices(self):
        import inspect
        from cantina import main
        src = inspect.getsource(main)
        assert '"deep"' in src
        assert "--background" in src
        assert "--status" in src

    def test_write_and_print_deep_status(self, tmp_path, capsys):
        from cantina import _write_deep_status, _print_deep_status, _deep_status_path
        _write_deep_status(tmp_path, state="running", phase="quick", pid=12345, target="10.10.10.1")
        path = _deep_status_path(tmp_path)
        assert path.exists()
        data = path.read_text(encoding="utf-8")
        assert "enumeration-only" in data
        assert "quick" in data
        _print_deep_status(tmp_path)
        out = capsys.readouterr().out
        assert "running" in out
        assert "quick" in out

    def test_run_deep_pipeline_phases_status(self, tmp_path, monkeypatch):
        """Deep pipeline marks phases without live nmap (stubbed scan methods)."""
        from cantina import Scanner, _run_deep_pipeline, _deep_status_path
        import types

        sc = Scanner("10.10.10.50", str(tmp_path), rate=4, resume=False)
        sc.tcp_ports = {
            22: {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH"},
            80: {"port": 80, "proto": "tcp", "service": "http", "version": "nginx"},
        }
        sc.udp_ports = {}
        sc.findings = []
        called = []

        def stub(name):
            def _fn(*a, **k):
                called.append(name)
            return _fn

        for meth in ("quick_scan", "full_scan", "udp_scan", "vuln_scan",
                     "searchsploit_scan", "service_recon"):
            setattr(sc, meth, stub(meth))

        args = types.SimpleNamespace(
            target="10.10.10.50",
            skip_udp=False,
            skip_vuln=False,
            skip_sploit=False,
            skip_recon=False,
        )
        _run_deep_pipeline(args, sc, str(tmp_path))
        assert "quick_scan" in called and "full_scan" in called
        status = __import__("json").loads(_deep_status_path(tmp_path).read_text(encoding="utf-8"))
        assert "quick" in status.get("phases_done", [])
        assert status.get("legal", "").startswith("enumeration-only")
