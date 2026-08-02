"""
Tests for Cantina v1.3 gap features.
Drives real shipped helpers: concurrency/timeouts, force-services,
vhost/subdomain decisions, service type selection, audit log.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── DeadlineClock ───────────────────────────────────────────────────────

class TestDeadlineClock:
    def test_cap_timeout_no_deadline(self):
        from cantina import DeadlineClock
        c = DeadlineClock()
        assert c.cap_timeout(100) == 100
        assert c.expired() is False

    def test_global_expiry(self):
        from cantina import DeadlineClock
        c = DeadlineClock(global_timeout_sec=0.05)
        time.sleep(0.07)
        assert c.expired() is True
        with pytest.raises(TimeoutError):
            c.cap_timeout(10)

    def test_target_timeout_caps(self):
        from cantina import DeadlineClock
        c = DeadlineClock(target_timeout_sec=0.08)
        c.begin_target()
        time.sleep(0.02)
        rem = c.remaining()
        assert rem is not None and rem < 0.08
        capped = c.cap_timeout(999)
        assert 1 <= capped <= 999


# ── Multi-target concurrency ────────────────────────────────────────────

class TestRunMultiTargets:
    def test_concurrent_workers_run_all(self):
        from cantina import run_multi_targets
        seen = []
        lock = __import__("threading").Lock()

        def worker(t):
            with lock:
                seen.append(t)
            time.sleep(0.05)
            return t * 2

        results = run_multi_targets(
            [1, 2, 3, 4], worker, max_workers=3, global_timeout_sec=5,
        )
        assert len(results) == 4
        assert all(r["status"] == "ok" for r in results)
        assert sorted(seen) == [1, 2, 3, 4]
        assert sorted(r["result"] for r in results) == [2, 4, 6, 8]

    def test_global_timeout_abandons_remaining(self):
        from cantina import run_multi_targets

        def slow(t):
            time.sleep(0.3)
            return t

        # Sequential workers so later targets still pending when global dies
        results = run_multi_targets(
            ["a", "b", "c", "d"],
            slow,
            max_workers=1,
            global_timeout_sec=0.35,
        )
        statuses = [r["status"] for r in results]
        assert "ok" in statuses
        assert "abandoned_global" in statuses

    def test_worker_timeout_status(self):
        from cantina import run_multi_targets

        def boom(t):
            raise TimeoutError("hung")

        results = run_multi_targets(["x"], boom, max_workers=1)
        assert results[0]["status"] == "timeout"


# ── Force-services / ports ──────────────────────────────────────────────

class TestForceServices:
    def test_parse_force_services_seeds_tcp_udp(self):
        from cantina import parse_force_services
        tcp, udp = parse_force_services(
            ["tcp/80/http", "445/microsoft-ds", "udp/53/domain", "tcp/443/https/nginx 1.18"]
        )
        assert 80 in tcp and tcp[80]["service"] == "http"
        assert 445 in tcp and tcp[445]["service"] == "microsoft-ds"
        assert 53 in udp and udp[53]["service"] == "domain"
        assert 443 in tcp and "nginx" in tcp[443]["version"]

    def test_parse_force_services_rejects_bad(self):
        from cantina import parse_force_services
        with pytest.raises(ValueError):
            parse_force_services(["not-a-spec"])
        with pytest.raises(ValueError):
            parse_force_services(["tcp/99999/http"])

    def test_parse_ports_spec(self):
        from cantina import parse_ports_spec
        tcp, udp = parse_ports_spec("80,443,T:22,U:53,161")
        assert 80 in tcp and 443 in tcp and 22 in tcp
        assert 53 in udp and 161 in udp

    def test_seed_ports_from_known_skip_flag(self):
        from cantina import seed_ports_from_known
        tcp, udp, skip = seed_ports_from_known(
            force_specs=["tcp/80/http"], ports_spec="445,U:161"
        )
        assert skip is True
        assert 80 in tcp and tcp[80]["service"] == "http"
        assert 445 in tcp  # unknown service from --ports
        assert 161 in udp

    def test_scanner_apply_known_ports(self, tmp_path):
        from cantina import Scanner
        sc = Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        skip = sc.apply_known_ports(
            ["tcp/80/http", "tcp/445/smb"], None
        )
        assert skip is True
        assert sc.skip_port_discovery is True
        assert set(sc.tcp_ports) == {80, 445}
        tasks = sc.build_recon_tasks()
        types = {t[0] for t in tasks}
        assert "http" in types
        assert "smb" in types


# ── Service type selection ──────────────────────────────────────────────

class TestSelectServiceType:
    def test_telnet_elasticsearch_kibana(self):
        from cantina import select_service_type
        assert select_service_type(23, "telnet") == "telnet"
        assert select_service_type(23, "") == "telnet"
        assert select_service_type(9200, "http") == "elasticsearch"
        assert select_service_type(5601, "http") == "kibana"
        assert select_service_type(22, "ssh") == "ssh"
        assert select_service_type(80, "http") == "http"

    def test_build_recon_tasks_includes_new_types(self, tmp_path):
        from cantina import Scanner, _port_record
        sc = Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        sc.tcp_ports = {
            23: _port_record(23, "tcp", "telnet", ""),
            9200: _port_record(9200, "tcp", "http", ""),
            5601: _port_record(5601, "tcp", "http", ""),
            80: _port_record(80, "tcp", "http", "nginx"),
        }
        tasks = sc.build_recon_tasks()
        types = {t[0] for t in tasks}
        assert "telnet" in types
        assert "elasticsearch" in types
        assert "kibana" in types
        assert "http" in types


# ── Vhost / subdomain decisions ─────────────────────────────────────────

class TestVhostSubdomain:
    def test_vhost_skip_no_domain(self):
        from cantina import decide_vhost_actions, actions_to_run
        acts = decide_vhost_actions(domain=None, wordlist_exists=True, tools_present={"ffuf"})
        assert actions_to_run(acts) == []
        assert "no domain" in acts[0]["reason"]

    def test_vhost_skip_no_wordlist(self):
        from cantina import decide_vhost_actions, actions_to_run
        acts = decide_vhost_actions(
            domain="box.htb", wordlist_exists=False, tools_present={"ffuf"}
        )
        assert actions_to_run(acts) == []
        assert "wordlist" in acts[0]["reason"]

    def test_vhost_run_when_ready(self):
        from cantina import decide_vhost_actions, actions_to_run
        acts = decide_vhost_actions(
            domain="box.htb",
            wordlist_exists=True,
            tools_present={"ffuf", "gobuster"},
            depth="normal",
        )
        ran = actions_to_run(acts)
        assert len(ran) == 1
        assert ran[0]["tool"] == "vhost_enum"
        assert ran[0]["via"] == "ffuf"

    def test_subdomain_skip_and_run(self):
        from cantina import decide_subdomain_actions, actions_to_run
        skip = decide_subdomain_actions(domain=None, wordlist_exists=True)
        assert actions_to_run(skip) == []
        run = decide_subdomain_actions(
            domain="htb", wordlist_exists=True, tools_present={"gobuster"}
        )
        assert actions_to_run(run)[0]["via"] == "gobuster"


# ── SNMP onesixtyone + SMB enum tool select ─────────────────────────────

class TestSnmpAndSmbSelect:
    def test_onesixtyone_in_decisions(self):
        from cantina import decide_snmp_actions, actions_to_run
        acts = decide_snmp_actions(valid_community=None, onesixtyone_available=True)
        tools = {a["tool"]: a for a in acts}
        assert tools["onesixtyone"]["run"] is True
        acts2 = decide_snmp_actions(valid_community="public", onesixtyone_available=True)
        tools2 = {a["tool"]: a for a in acts2}
        assert tools2["onesixtyone"]["run"] is False
        assert tools2["snmpwalk_deep"]["run"] is True

    def test_enum4linux_ng_preferred(self):
        from cantina import select_smb_enum_tool
        assert select_smb_enum_tool({"enum4linux", "enum4linux-ng"}) == "enum4linux-ng"
        assert select_smb_enum_tool({"enum4linux"}) == "enum4linux"
        assert select_smb_enum_tool(set()) is None


# ── Command audit log ───────────────────────────────────────────────────

class TestCommandAuditLog:
    def test_audit_writes_file(self, tmp_path):
        from cantina import CommandAuditLog
        log = CommandAuditLog(tmp_path / "_commands.log")
        log.log("nmap -sV 10.0.0.1", rc=0, duration_s=1.5, note="test")
        text = (tmp_path / "_commands.log").read_text(encoding="utf-8")
        assert "nmap -sV 10.0.0.1" in text
        assert "rc=0" in text

    def test_run_audits_when_set(self, tmp_path):
        import cantina
        log = cantina.CommandAuditLog(tmp_path / "_commands.log")
        cantina.set_command_audit(log)
        try:
            # harmless command on Windows/Linux
            out, err, rc = cantina.run("echo cantina-audit-probe", timeout=10)
            text = (tmp_path / "_commands.log").read_text(encoding="utf-8")
            assert "echo cantina-audit-probe" in text or "cantina-audit" in text
        finally:
            cantina.set_command_audit(None)


# ── Real-path concurrent audit + hard deadline (shipped run/TLS) ────────

class TestRealPathConcurrencyAndDeadline:
    def test_concurrent_run_audit_isolation(self, tmp_path):
        """Workers install thread-local audit; run() must not cross-contaminate logs."""
        import cantina

        hosts = ["h1", "h2", "h3"]

        def worker(host, target_timeout_sec=None):
            outdir = tmp_path / host
            outdir.mkdir(parents=True, exist_ok=True)
            audit = cantina.CommandAuditLog(outdir / "_commands.log")
            cantina.set_command_audit(audit)
            try:
                marker = f"echo CANTINA_AUDIT_{host}"
                for _ in range(8):
                    cantina.run(marker, timeout=15)
                    time.sleep(0.005)
                return str(outdir)
            finally:
                cantina.set_command_audit(None)

        results = cantina.run_multi_targets(hosts, worker, max_workers=3)
        assert all(r["status"] == "ok" for r in results), results
        for host in hosts:
            text = (tmp_path / host / "_commands.log").read_text(encoding="utf-8")
            assert f"CANTINA_AUDIT_{host}" in text
            for other in hosts:
                if other != host:
                    assert f"CANTINA_AUDIT_{other}" not in text, (
                        f"{host} log leaked {other}: {text!r}"
                    )

    def test_deadline_raises_from_run_and_multi_status_timeout(self, tmp_path):
        """Expired thread-local DeadlineClock makes run() raise; multi status=timeout."""
        import cantina

        def worker(host, target_timeout_sec=None):
            outdir = tmp_path / host
            outdir.mkdir(parents=True, exist_ok=True)
            audit = cantina.CommandAuditLog(outdir / "_commands.log")
            clock = cantina.DeadlineClock(target_timeout_sec=0.05)
            clock.begin_target()
            cantina.set_command_audit(audit)
            cantina.set_deadline_clock(clock)
            try:
                time.sleep(0.08)
                # Must hard-abandon, not soft [DEADLINE] return
                cantina.run(f"echo DEADLINE_SHOULD_RAISE_{host}", timeout=30)
                return "unexpected_ok"
            finally:
                cantina.set_command_audit(None)
                cantina.set_deadline_clock(None)

        results = cantina.run_multi_targets(
            ["x", "y"], worker, max_workers=2, target_timeout_sec=0.05,
        )
        assert all(r["status"] == "timeout" for r in results), results
        for host in ("x", "y"):
            text = (tmp_path / host / "_commands.log").read_text(encoding="utf-8")
            assert "deadline_expired" in text

    def test_run_raises_timeout_error_not_soft_return(self):
        import cantina
        clock = cantina.DeadlineClock(target_timeout_sec=0.03)
        clock.begin_target()
        cantina.set_deadline_clock(clock)
        try:
            time.sleep(0.05)
            with pytest.raises(TimeoutError):
                cantina.run("echo soft-return-is-a-bug", timeout=60)
        finally:
            cantina.set_deadline_clock(None)

    def test_run_tasks_isolated_inherits_audit_tls(self, tmp_path):
        """Concurrent recon pool must inherit parent-thread audit into workers."""
        import cantina

        log_path = tmp_path / "_commands.log"
        audit = cantina.CommandAuditLog(log_path)
        cantina.set_command_audit(audit)
        try:
            def worker(task):
                # Must see parent audit via inherit_tls in run_tasks_isolated
                cantina.run(f"echo RECON_POOL_{task}", timeout=15)
                return task

            results = cantina.run_tasks_isolated(
                ["ssh", "http", "smb"], worker, max_workers=3, inherit_tls=True,
            )
            assert all(r["ok"] for r in results), results
            text = log_path.read_text(encoding="utf-8")
            for name in ("ssh", "http", "smb"):
                assert f"RECON_POOL_{name}" in text, text
            # parent TLS restored after pool
            assert cantina.get_command_audit() is audit
        finally:
            cantina.set_command_audit(None)


# ── Per-port layout ─────────────────────────────────────────────────────

class TestPerPortLayout:
    def test_port_recon_subdir(self, tmp_path):
        from cantina import port_recon_subdir
        d = port_recon_subdir(tmp_path / "recon", 80, "tcp")
        assert d.name == "tcp80"
        assert d.is_dir()
        d2 = port_recon_subdir(tmp_path / "recon", 53, "udp")
        assert d2.name == "udp53"


# ── CLI help documents flags ────────────────────────────────────────────

class TestCliHelp:
    def test_help_lists_gap_flags(self):
        import subprocess
        import sys
        from pathlib import Path
        script = Path(__file__).parent.parent / "cantina.py"
        r = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0
        help_text = r.stdout + r.stderr
        for flag in (
            "--max-workers", "--timeout", "--target-timeout",
            "--force-services", "--ports",
            "--dirbust-tool", "--dirbust-wordlist",
            "--vhost-domain", "--subdomain-domain",
        ):
            assert flag in help_text, f"missing {flag} in --help"

    def test_module_still_oscp_enum_only(self):
        import cantina
        assert "Enumeration only" in cantina.__doc__
        assert "No exploitation" in cantina.__doc__
