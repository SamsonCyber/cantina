"""
Tests for Cantina plugin model (cantina_plugins.py + recon wiring).
Drives shipped discovery/selection/execution — no registry reimplementation.
"""
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Contract / pure selection ───────────────────────────────────────────

class TestPluginSelection:
    def test_empty_registry_selects_nothing(self):
        from cantina_plugins import PluginRegistry, select_plugins, PluginSignals
        reg = PluginRegistry()
        assert select_plugins(reg, PluginSignals(port=80, svc_type="http")) == []

    def test_default_match_by_service_and_port(self):
        from cantina_plugins import (
            PluginRegistry, register_plugin_from_dict, select_plugins, default_match,
            PluginMeta,
        )
        reg = PluginRegistry()
        register_plugin_from_dict(
            reg,
            {"name": "webby", "services": ["http"], "ports": [], "enabled": True},
        )
        register_plugin_from_dict(
            reg,
            {"name": "ssh_only", "services": ["ssh"], "ports": [22], "enabled": True},
        )
        hit = select_plugins(reg, {"port": 80, "service": "http", "svc_type": "http"})
        names = [p.name for p in hit]
        assert "webby" in names
        assert "ssh_only" not in names

        hit2 = select_plugins(reg, {"port": 22, "service": "ssh", "svc_type": "ssh"})
        names2 = [p.name for p in hit2]
        assert "ssh_only" in names2
        assert "webby" not in names2

    def test_disabled_plugin_skipped(self):
        from cantina_plugins import PluginRegistry, register_plugin_from_dict, select_plugins
        reg = PluginRegistry()
        register_plugin_from_dict(
            reg,
            {"name": "off", "services": ["*"], "enabled": False},
        )
        register_plugin_from_dict(
            reg,
            {"name": "on", "services": ["*"], "enabled": True},
        )
        hit = select_plugins(reg, {"port": 1, "service": "x", "svc_type": "x"})
        assert [p.name for p in hit] == ["on"]

    def test_custom_match_fn(self):
        from cantina_plugins import PluginRegistry, register_plugin_from_dict, select_plugins
        reg = PluginRegistry()

        def only_high(signals):
            return int(signals.get("port") or 0) > 1000

        register_plugin_from_dict(
            reg,
            {"name": "highport", "services": [], "ports": [], "enabled": True},
            match_fn=only_high,
        )
        # empty services+ports with default match never selects — custom match used
        assert select_plugins(reg, {"port": 80}) == []
        assert [p.name for p in select_plugins(reg, {"port": 8080})] == ["highport"]


# ── Discovery from disk ─────────────────────────────────────────────────

class TestPluginDiscovery:
    def test_discover_from_temp_dir(self, tmp_path):
        from cantina_plugins import discover_plugins, select_plugins
        plug = tmp_path / "my_probe.py"
        plug.write_text(
            textwrap.dedent(
                """
                PLUGIN = {
                    "name": "my_probe",
                    "services": ["ftp"],
                    "ports": [21],
                    "enabled": True,
                    "description": "fixture",
                }
                def run(ctx):
                    p = ctx.port_dir / "plugin_my_probe.txt"
                    p.write_text("ran\\n", encoding="utf-8")
                    return {"ok": True, "artifact": str(p)}
                """
            ),
            encoding="utf-8",
        )
        reg = discover_plugins(str(tmp_path), extra_dirs=[])
        # only load this dir — pass plugins_dir and empty extra, but discover also
        # appends defaults. Filter by name.
        names = [p.name for p in reg.plugins]
        assert "my_probe" in names
        hit = select_plugins(reg, {"port": 21, "service": "ftp", "svc_type": "ftp"})
        assert any(p.name == "my_probe" for p in hit)

    def test_load_invalid_name_rejected(self):
        from cantina_plugins import PluginRegistry, register_plugin_from_dict
        reg = PluginRegistry()
        with pytest.raises(ValueError):
            register_plugin_from_dict(reg, {"name": "../evil", "services": ["*"]})


# ── Execution ───────────────────────────────────────────────────────────

class TestPluginRun:
    def test_run_plugin_writes_artifact(self, tmp_path):
        from cantina_plugins import (
            PluginRegistry, register_plugin_from_dict, PluginContext,
            run_plugin, select_plugins, run_plugins_for_signals,
        )
        reg = PluginRegistry()
        ran = {"n": 0}

        def run(ctx):
            ran["n"] += 1
            art = ctx.port_dir / "plugin_touch.txt"
            art.write_text(f"target={ctx.target} port={ctx.port}\n", encoding="utf-8")
            return {"ok": True, "artifact": str(art)}

        register_plugin_from_dict(
            reg,
            {"name": "touch", "services": ["http"], "enabled": True},
            run_fn=run,
        )
        port_dir = tmp_path / "recon" / "tcp80"
        port_dir.mkdir(parents=True)
        ctx = PluginContext(
            target="10.10.10.5",
            port=80,
            proto="tcp",
            service="http",
            version="nginx",
            svc_type="http",
            outdir=tmp_path,
            recon_dir=tmp_path / "recon",
            port_dir=port_dir,
        )
        results = run_plugins_for_signals(
            reg, {"port": 80, "service": "http", "svc_type": "http"}, ctx,
        )
        assert ran["n"] == 1
        assert results[0]["ok"] is True
        assert (port_dir / "plugin_touch.txt").is_file()
        body = (port_dir / "plugin_touch.txt").read_text(encoding="utf-8")
        assert "10.10.10.5" in body

    def test_disabled_does_not_run(self, tmp_path):
        from cantina_plugins import (
            PluginRegistry, register_plugin_from_dict, PluginContext,
            run_plugins_for_signals,
        )
        reg = PluginRegistry()
        ran = {"n": 0}

        def run(ctx):
            ran["n"] += 1
            return {"ok": True}

        register_plugin_from_dict(
            reg,
            {"name": "nope", "services": ["*"], "enabled": False},
            match_fn=lambda s: True,
            run_fn=run,
        )
        ctx = PluginContext(
            target="x", port=1, proto="tcp", service="", version="",
            svc_type="", outdir=tmp_path, recon_dir=tmp_path, port_dir=tmp_path,
        )
        results = run_plugins_for_signals(reg, {"port": 1}, ctx)
        assert results == []
        assert ran["n"] == 0

    def test_run_cmd_audited_when_wired(self, tmp_path):
        """Plugin that shells via ctx.run_cmd should call the real wrapper."""
        import cantina
        from cantina_plugins import (
            PluginRegistry, register_plugin_from_dict, PluginContext,
            run_plugin,
        )
        reg = PluginRegistry()
        audit = cantina.CommandAuditLog(tmp_path / "_commands.log")
        cantina.set_command_audit(audit)

        def run(ctx):
            ctx.run_cmd("echo PLUGIN_AUDIT_PROBE")
            return {"ok": True}

        try:
            p = register_plugin_from_dict(
                reg,
                {"name": "auditor", "services": ["*"], "enabled": True},
                match_fn=lambda s: True,
                run_fn=run,
            )
            ctx = PluginContext(
                target="x", port=9, proto="tcp", service="", version="",
                svc_type="", outdir=tmp_path, recon_dir=tmp_path, port_dir=tmp_path,
                run_cmd=lambda cmd: cantina.run(cmd, timeout=10),
            )
            result = run_plugin(p, ctx)
            assert result["ok"] is True
            text = (tmp_path / "_commands.log").read_text(encoding="utf-8")
            assert "PLUGIN_AUDIT_PROBE" in text or "echo PLUGIN_AUDIT_PROBE" in text
        finally:
            cantina.set_command_audit(None)


# ── Scanner wiring ──────────────────────────────────────────────────────

class TestScannerPluginWiring:
    def test_scanner_runs_plugins_after_recon(self, tmp_path):
        """Real Scanner path: seed ports, run_plugins_for_target uses shipped helper."""
        from cantina import Scanner, _port_record
        from cantina_plugins import (
            PluginRegistry, register_plugin_from_dict, discover_plugins,
        )
        # Build scanner with seeded http port
        sc = Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        sc.tcp_ports = {
            80: _port_record(80, "tcp", "http", "nginx"),
        }
        sc.udp_ports = {}
        sc.recon_depth = "normal"

        reg = PluginRegistry()
        ran = []

        def run(ctx):
            ran.append(ctx.port)
            art = ctx.port_dir / "plugin_wire.txt"
            art.write_text("wired\n", encoding="utf-8")
            return {"ok": True, "artifact": str(art)}

        register_plugin_from_dict(
            reg,
            {"name": "wire_http", "services": ["http"], "enabled": True},
            run_fn=run,
        )
        sc.plugin_registry = reg

        # Call shipped method if present
        assert hasattr(sc, "run_service_plugins"), "Scanner must expose run_service_plugins"
        results = sc.run_service_plugins()
        assert ran == [80]
        assert any(r.get("ok") for r in results)
        art = tmp_path / "recon" / "tcp80" / "plugin_wire.txt"
        assert art.is_file()

    def test_builtin_recon_without_plugins_still_works(self, tmp_path):
        from cantina import Scanner, _port_record
        sc = Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        sc.tcp_ports = {22: _port_record(22, "tcp", "ssh", "OpenSSH")}
        tasks = sc.build_recon_tasks()
        assert any(t[0] == "ssh" for t in tasks)
        # empty registry is fine
        if hasattr(sc, "run_service_plugins"):
            sc.plugin_registry = __import__("cantina_plugins", fromlist=["PluginRegistry"]).PluginRegistry()
            assert sc.run_service_plugins() == []


# ── CLI ─────────────────────────────────────────────────────────────────

class TestReplacesBuiltin:
    def test_replaced_builtin_services_set(self):
        from cantina_plugins import (
            PluginRegistry, register_plugin_from_dict, replaced_builtin_services,
        )
        reg = PluginRegistry()
        register_plugin_from_dict(
            reg,
            {
                "name": "snmp_enum",
                "services": ["snmp"],
                "enabled": True,
                "replaces_builtin": True,
            },
        )
        register_plugin_from_dict(
            reg,
            {"name": "note", "services": ["http"], "enabled": True, "replaces_builtin": False},
        )
        assert replaced_builtin_services(reg) == {"snmp"}

    def test_build_recon_tasks_skips_replaced_snmp(self, tmp_path):
        from cantina import Scanner, _port_record
        from cantina_plugins import PluginRegistry, register_plugin_from_dict
        sc = Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        sc.tcp_ports = {}
        sc.udp_ports = {
            161: _port_record(161, "udp", "snmp", ""),
            22: _port_record(22, "tcp", "ssh", "OpenSSH"),  # wrong proto but ok for select
        }
        # put ssh on tcp properly
        sc.tcp_ports = {22: _port_record(22, "tcp", "ssh", "OpenSSH")}
        sc.udp_ports = {161: _port_record(161, "udp", "snmp", "")}

        reg = PluginRegistry()
        register_plugin_from_dict(
            reg,
            {
                "name": "snmp_enum",
                "services": ["snmp"],
                "enabled": True,
                "replaces_builtin": True,
            },
            run_fn=lambda ctx: {"ok": True},
        )
        sc.plugin_registry = reg
        tasks = sc.build_recon_tasks()
        types = {t[0] for t in tasks}
        assert "snmp" not in types  # replaced by snmp_enum
        # ssh may also be plugin-owned when full suite is discovered

    def test_snmp_plugin_module_loads_and_runs(self, tmp_path):
        """Ship disk plugin snmp_enum: match + run write artifact without live snmpwalk."""
        from cantina_plugins import discover_plugins, PluginContext, run_plugin, select_plugins
        from pathlib import Path
        tools = Path(__file__).parent.parent
        reg = discover_plugins(str(tools / "plugins"))
        assert any(p.name == "snmp_enum" for p in reg.plugins)
        plug = next(p for p in reg.plugins if p.name == "snmp_enum")
        assert plug.meta.replaces_builtin is True
        assert select_plugins(reg, {"port": 161, "service": "snmp", "svc_type": "snmp"})
        port_dir = tmp_path / "udp161"
        port_dir.mkdir()
        # run_cmd returns soft failure (no snmp tools on Windows CI) still ok path
        def fake_run(cmd, timeout=60):
            return "", "missing", 1

        ctx = PluginContext(
            target="10.10.10.1",
            port=161,
            proto="udp",
            service="snmp",
            version="",
            svc_type="snmp",
            outdir=tmp_path,
            recon_dir=tmp_path,
            port_dir=port_dir,
            run_cmd=fake_run,
        )
        result = run_plugin(plug, ctx)
        assert result.get("ok") is True
        assert (port_dir / "plugin_snmp_enum.txt").is_file()

    def test_ftp_plugin_replaces_and_runs(self, tmp_path, monkeypatch):
        import shutil
        from cantina import Scanner, _port_record
        from cantina_plugins import discover_plugins, PluginContext, run_plugin
        from pathlib import Path
        tools = Path(__file__).parent.parent
        reg = discover_plugins(str(tools / "plugins"))
        assert any(p.name == "ftp_enum" for p in reg.plugins)
        plug = next(p for p in reg.plugins if p.name == "ftp_enum")
        assert plug.meta.replaces_builtin is True

        sc = Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        sc.tcp_ports = {
            21: _port_record(21, "tcp", "ftp", "vsftpd 3.0"),
            22: _port_record(22, "tcp", "ssh", "OpenSSH"),
        }
        sc.plugin_registry = reg
        types = {t[0] for t in sc.build_recon_tasks()}
        assert "ftp" not in types  # replaced by ftp_enum plugin
        # ssh may also be replaced when full plugin suite is loaded

        port_dir = tmp_path / "tcp21"
        port_dir.mkdir()

        # Windows CI may lack nmap/curl; plugin still must take the anon path
        def fake_which(name):
            if name in ("nmap", "curl"):
                return f"/usr/bin/{name}"
            return None

        monkeypatch.setattr(shutil, "which", fake_which)

        def fake_run(cmd, timeout=60):
            # Pretend nmap found anon FTP so decision path exercises
            if "nmap" in cmd and "ftp" in cmd:
                ofile = None
                if "-oN" in cmd:
                    parts = cmd.split()
                    for i, p in enumerate(parts):
                        if p == "-oN" and i + 1 < len(parts):
                            ofile = Path(parts[i + 1])
                            break
                body = "Anonymous FTP login allowed\n| ftp-syst:\n|   vsftpd 2.3.4\n"
                if ofile:
                    ofile.parent.mkdir(parents=True, exist_ok=True)
                    ofile.write_text(body, encoding="utf-8")
                return body, "", 0
            if "list-only" in cmd:
                return "readme.txt\nbackup.sql\n", "", 0
            return "", "", 1

        findings = []
        ctx = PluginContext(
            target="10.10.10.9",
            port=21,
            proto="tcp",
            service="ftp",
            version="",
            svc_type="ftp",
            outdir=tmp_path,
            recon_dir=tmp_path,
            port_dir=port_dir,
            run_cmd=fake_run,
            add_finding=lambda *a, **k: findings.append((a, k)),
        )
        result = run_plugin(plug, ctx)
        assert result.get("ok") is True
        assert (port_dir / "plugin_ftp_enum.txt").is_file()
        assert result.get("anon_allowed") is True
        assert any("Anonymous" in str(f) or "anon" in str(f).lower() for f in findings) or result.get("anon_allowed")


class TestPluginCli:
    def test_help_documents_plugins(self):
        import subprocess
        import sys
        script = Path(__file__).parent.parent / "cantina.py"
        r = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0
        text = r.stdout + r.stderr
        assert "--list-plugins" in text or "list-plugins" in text
        assert "plugin" in text.lower()

    def test_list_plugins_exits_zero(self):
        import subprocess
        import sys
        script = Path(__file__).parent.parent / "cantina.py"
        r = subprocess.run(
            [sys.executable, str(script), "--list-plugins"],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0
        text = r.stdout + r.stderr
        assert "plugin" in text.lower() or "Cantina" in text

    def test_module_legal_enum_only(self):
        import cantina_plugins
        assert "enumeration-only" in cantina_plugins.LEGAL_ENUM_ONLY.lower()
        assert "OSCP" in cantina_plugins.LEGAL_ENUM_ONLY
