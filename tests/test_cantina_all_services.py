"""
Prove every select_service_type value has a replacing plugin that match/run works.
Drives real discovery + plugin.run with stubbed tools (no live nmap required).
"""
from __future__ import annotations

import inspect
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

TOOLS = Path(__file__).parent.parent
SCRATCH = Path(r"C:\Users\shotg\AppData\Local\Temp\grok-goal-03a4f6750efa\implementer")


def _all_service_types():
    import cantina
    src = inspect.getsource(cantina.select_service_type)
    return sorted(set(re.findall(r"return ['\"]([a-z_]+)['\"]", src)))


def _port_for(svc: str) -> tuple[int, str]:
    """Representative port/proto for a service type."""
    mapping = {
        "http": (80, "tcp"),
        "ftp": (21, "tcp"),
        "ssh": (22, "tcp"),
        "telnet": (23, "tcp"),
        "smtp": (25, "tcp"),
        "dns": (53, "udp"),
        "tftp": (69, "udp"),
        "mail": (110, "tcp"),
        "rpc": (111, "tcp"),
        "smb": (445, "tcp"),
        "snmp": (161, "udp"),
        "ldap": (389, "tcp"),
        "rsync": (873, "tcp"),
        "mssql": (1433, "tcp"),
        "nfs": (2049, "tcp"),
        "mysql": (3306, "tcp"),
        "rdp": (3389, "tcp"),
        "postgresql": (5432, "tcp"),
        "vnc": (5900, "tcp"),
        "winrm": (5985, "tcp"),
        "couchdb": (5984, "tcp"),
        "redis": (6379, "tcp"),
        "kerberos": (88, "tcp"),
        "kibana": (5601, "tcp"),
        "elasticsearch": (9200, "tcp"),
        "memcached": (11211, "tcp"),
        "mongodb": (27017, "tcp"),
    }
    return mapping.get(svc, (1, "tcp"))


@pytest.fixture(scope="module")
def registry():
    from cantina_plugins import discover_plugins
    return discover_plugins(str(TOOLS / "plugins"))


@pytest.fixture(scope="module")
def service_types():
    return _all_service_types()


class TestAllServicesInventory:
    def test_every_service_has_replacing_plugin(self, registry, service_types):
        from cantina_plugins import replaced_builtin_services
        replaced = replaced_builtin_services(registry)
        # http may be covered by http_enum; mail covers pop/imap via mail svc_type
        missing = []
        for svc in service_types:
            # find enabled plugin that matches this svc_type
            port, proto = _port_for(svc)
            signals = {
                "port": port,
                "proto": proto,
                "service": svc,
                "version": "",
                "svc_type": svc,
            }
            from cantina_plugins import select_plugins
            hits = select_plugins(registry, signals)
            # Prefer replaces_builtin owners
            owners = [p for p in hits if p.meta.replaces_builtin and p.meta.enabled]
            if not owners:
                missing.append(svc)
        inv_lines = []
        for svc in service_types:
            port, proto = _port_for(svc)
            signals = {
                "port": port, "proto": proto, "service": svc,
                "version": "", "svc_type": svc,
            }
            from cantina_plugins import select_plugins
            hits = select_plugins(registry, signals)
            owners = [p for p in hits if p.meta.replaces_builtin and p.meta.enabled]
            status = "plugin" if owners else "MISSING"
            names = ",".join(p.name for p in owners) if owners else "-"
            inv_lines.append(f"{svc}\t{status}\treplace={bool(owners)}\tplugins={names}")
        SCRATCH.mkdir(parents=True, exist_ok=True)
        (SCRATCH / "cantina_services_inventory.txt").write_text(
            "\n".join(inv_lines) + "\n", encoding="utf-8",
        )
        assert not missing, f"services without replaces_builtin plugin: {missing}"
        assert "snmp" in replaced and "ftp" in replaced


class TestAllServicesRun:
    @pytest.mark.parametrize("svc", _all_service_types())
    def test_service_plugin_run_writes_artifact(self, registry, svc, tmp_path, monkeypatch):
        """Real plugin.run for each service with stubbed tools."""
        from cantina_plugins import select_plugins, run_plugin, PluginContext

        def fake_which(name):
            # Pretend common tools exist so nmap/curl branches execute stubs
            return f"/usr/bin/{name}"

        monkeypatch.setattr(shutil, "which", fake_which)

        port, proto = _port_for(svc)
        signals = {
            "port": port,
            "proto": proto,
            "service": svc,
            "version": "test 1.0",
            "svc_type": svc,
        }
        hits = [
            p for p in select_plugins(registry, signals)
            if p.meta.replaces_builtin and p.meta.enabled
        ]
        assert hits, f"no replacing plugin for {svc}"
        plug = hits[0]

        port_dir = tmp_path / f"{proto}{port}"
        port_dir.mkdir(parents=True)

        def fake_run(cmd, timeout=60):
            # Write nmap -oN files when requested so plugins that read them work
            if "-oN" in cmd:
                parts = cmd.split()
                for i, p in enumerate(parts):
                    if p == "-oN" and i + 1 < len(parts):
                        ofile = Path(parts[i + 1])
                        ofile.parent.mkdir(parents=True, exist_ok=True)
                        body = (
                            f"# stub nmap for {svc}\n"
                            f"Anonymous FTP login allowed\n"
                            f"VULNERABLE\n"
                            f"redis_version:7.0\n"
                            f"cluster_name : test\n"
                            f"DNS_Computer_Name: HOST\n"
                            f"empty-password\n"
                        )
                        ofile.write_text(body, encoding="utf-8")
                        return body, "", 0
            if "curl" in cmd and "list-only" in cmd:
                return "readme.txt\n", "", 0
            if "curl" in cmd:
                return "HTTP/1.1 200 OK\nServer: nginx\n\n<html><title>t</title></html>", "", 0
            if "smbclient" in cmd:
                return "Sharename\nDisk\n", "", 0
            if "redis-cli" in cmd and "PING" in cmd:
                return "PONG", "", 0
            if "redis-cli" in cmd and "INFO" in cmd:
                return "redis_version:7.0\n", "", 0
            if "showmount" in cmd:
                return "Export list for x:\n/home *\n", "", 0
            if "rsync" in cmd:
                return "module1\t\tModule one\n", "", 0
            if "ldapsearch" in cmd and "namingContexts" in cmd:
                return "namingContexts: dc=test,dc=local\n", "", 0
            return "ok", "", 0

        findings = []
        ctx = PluginContext(
            target="10.10.10.50",
            port=port,
            proto=proto,
            service=svc,
            version="test 1.0",
            svc_type=svc,
            outdir=tmp_path,
            recon_dir=tmp_path / "recon",
            port_dir=port_dir,
            depth="normal",
            run_cmd=fake_run,
            add_finding=lambda *a, **k: findings.append(a),
        )
        (tmp_path / "recon").mkdir(exist_ok=True)
        result = run_plugin(plug, ctx)
        assert result.get("ok") is True, f"{svc} plugin failed: {result}"
        art = result.get("artifact")
        assert art, f"{svc} produced no artifact: {result}"
        assert Path(art).is_file(), f"{svc} artifact missing: {art}"
        assert Path(art).stat().st_size > 0


class TestBuiltinSkip:
    def test_build_recon_tasks_skips_all_replaced(self, registry, tmp_path):
        from cantina import Scanner, _port_record
        from cantina_plugins import replaced_builtin_services
        sc = Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        sc.plugin_registry = registry
        # seed one port per major service
        seeds = {
            21: ("ftp", "tcp"),
            22: ("ssh", "tcp"),
            80: ("http", "tcp"),
            445: ("smb", "tcp"),
            161: ("snmp", "udp"),
            9200: ("http", "tcp"),  # ES classifier wins on port
        }
        sc.tcp_ports = {}
        sc.udp_ports = {}
        for port, (svc, proto) in seeds.items():
            rec = _port_record(port, proto, svc, "")
            if proto == "udp":
                sc.udp_ports[port] = rec
            else:
                sc.tcp_ports[port] = rec
        # Force ES service name on 9200
        sc.tcp_ports[9200] = _port_record(9200, "tcp", "elasticsearch", "")
        replaced = replaced_builtin_services(registry)
        tasks = sc.build_recon_tasks()
        types = {t[0] for t in tasks}
        # none of the replaced service types should appear as built-in tasks
        for svc in ("ftp", "ssh", "http", "smb", "snmp", "elasticsearch"):
            if svc in replaced:
                assert svc not in types, f"built-in task still present for {svc}: {tasks}"
