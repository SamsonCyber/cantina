"""
Speed + effectiveness optimizations: tool cache, plugin job planning,
parallel plugin phase, decision heavy-skip fidelity.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
SCRATCH = Path(r"C:\Users\shotg\AppData\Local\Temp\grok-goal-16fd57b707a3\implementer")


class TestToolExistsCache:
    def test_cache_hits_second_call(self, monkeypatch):
        import cantina
        cantina.clear_tool_exists_cache()
        calls = {"n": 0}
        real = cantina.shutil.which

        def counted(name):
            calls["n"] += 1
            return "/bin/fake" if name == "nmap" else None

        monkeypatch.setattr(cantina.shutil, "which", counted)
        assert cantina.tool_exists("nmap") is True
        assert cantina.tool_exists("nmap") is True
        assert calls["n"] == 1  # second call cached
        cantina.clear_tool_exists_cache()
        assert cantina.tool_exists("nmap") is True
        assert calls["n"] == 2


class TestPlanPluginJobs:
    def test_plan_dedupes_and_orders(self):
        from cantina_plugins import (
            PluginRegistry, register_plugin_from_dict, plan_plugin_jobs,
        )
        import cantina
        reg = PluginRegistry()
        register_plugin_from_dict(
            reg,
            {"name": "a", "services": ["http"], "enabled": True, "priority": 10},
            run_fn=lambda c: {"ok": True},
        )
        register_plugin_from_dict(
            reg,
            {"name": "b", "services": ["ssh"], "enabled": True, "priority": 10},
            run_fn=lambda c: {"ok": True},
        )
        ports = {
            80: {"port": 80, "proto": "tcp", "service": "http", "version": ""},
            22: {"port": 22, "proto": "tcp", "service": "ssh", "version": ""},
        }
        jobs = plan_plugin_jobs(ports, reg, cantina.select_service_type)
        names = [(j["plugin_name"], j["port"]) for j in jobs]
        assert ("a", 80) in names
        assert ("b", 22) in names
        # stable by port
        ports_order = [j["port"] for j in jobs]
        assert ports_order == sorted(ports_order)


class TestParallelPluginPhase:
    def test_plugin_jobs_run_concurrent_faster_than_serial(self, tmp_path):
        """Stubbed plugin sleeps 0.08s; 3 jobs with workers=3 finish ~serial/3."""
        import cantina
        from cantina_plugins import PluginRegistry, register_plugin_from_dict

        reg = PluginRegistry()
        sleep_s = 0.08

        def slow_run(ctx):
            time.sleep(sleep_s)
            art = Path(ctx.port_dir) / f"plugin_slow.txt"
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text("ok\n", encoding="utf-8")
            return {"ok": True, "artifact": str(art)}

        for name, svc, port in (("p1", "ssh", 22), ("p2", "ftp", 21), ("p3", "http", 80)):
            register_plugin_from_dict(
                reg,
                {"name": name, "services": [svc], "enabled": True, "priority": 10},
                run_fn=slow_run,
            )

        sc = cantina.Scanner("10.10.10.9", str(tmp_path), rate=4, resume=False)
        sc.plugin_registry = reg
        sc.recon_workers = 3
        sc.tcp_ports = {
            22: cantina._port_record(22, "tcp", "ssh", ""),
            21: cantina._port_record(21, "tcp", "ftp", ""),
            80: cantina._port_record(80, "tcp", "http", ""),
        }
        t0 = time.perf_counter()
        results = sc.run_service_plugins()
        elapsed = time.perf_counter() - t0
        assert len([r for r in results if r.get("ok")]) == 3
        # Parallel should beat 3 * sleep (allow overhead, still under 2.2x one sleep)
        serial_floor = sleep_s * 3
        assert elapsed < serial_floor * 0.75, (
            f"expected parallel speedup, elapsed={elapsed:.3f}s serial~{serial_floor:.3f}s"
        )
        SCRATCH.mkdir(parents=True, exist_ok=True)
        (SCRATCH / "cantina_speed_compare.txt").write_text(
            f"parallel_plugin_jobs elapsed_s={elapsed:.4f}\n"
            f"serial_floor_s={serial_floor:.4f}\n"
            f"speedup_factor={serial_floor/elapsed:.2f}x\n"
            f"jobs=3 workers=3\n",
            encoding="utf-8",
        )


class TestEffectivenessDecisions:
    def test_non_http_skips_heavy(self):
        from cantina import decide_http_actions, parse_http_probe
        from cantina_plugins import actions_heavy_skipped, actions_light_run
        sig = parse_http_probe("", "")  # not looks_http
        acts = decide_http_actions(sig, depth="normal", port=80, tools_present=None)
        heavy_skip = actions_heavy_skipped(acts)
        assert "dirbust" in heavy_skip or any(
            a["tool"] == "dirbust" and not a["run"] for a in acts
        )
        assert not any(a["tool"] == "dirbust" and a["run"] for a in acts)

    def test_tiny_banner_skips_dirbust_nikto(self):
        from cantina import decide_http_actions
        sig = {
            "looks_http": True,
            "status": 200,
            "server": "x",
            "tiny_banner": True,
            "real_app": False,
            "cms": None,
        }
        acts = decide_http_actions(sig, depth="normal", port=80)
        assert any(a["tool"] == "dirbust" and not a["run"] for a in acts)
        assert any(a["tool"] == "nikto" and not a["run"] for a in acts)

    def test_quick_depth_blocks_heavy_even_on_real_app(self):
        from cantina import decide_http_actions
        sig = {
            "looks_http": True,
            "status": 200,
            "server": "nginx",
            "tiny_banner": False,
            "real_app": True,
            "cms": None,
        }
        acts = decide_http_actions(sig, depth="quick", port=80)
        assert any(a["tool"] == "dirbust" and not a["run"] for a in acts)
        # whatweb is light and should still run
        assert any(a["tool"] == "whatweb" and a["run"] for a in acts)

    def test_real_app_normal_runs_dirbust(self):
        from cantina import decide_http_actions
        sig = {
            "looks_http": True,
            "status": 200,
            "server": "nginx",
            "tiny_banner": False,
            "real_app": True,
            "cms": None,
            "has_html": True,
            "body_len": 500,
        }
        acts = decide_http_actions(sig, depth="normal", port=80)
        assert any(a["tool"] == "dirbust" and a["run"] for a in acts)


class TestNoDoubleRun:
    def test_replaced_services_not_in_builtin_tasks(self, tmp_path):
        import cantina
        from cantina_plugins import discover_plugins, replaced_builtin_services
        reg = discover_plugins(str(Path(__file__).parent.parent / "plugins"))
        sc = cantina.Scanner("10.1.1.1", str(tmp_path), rate=4, resume=False)
        sc.plugin_registry = reg
        sc.tcp_ports = {
            22: cantina._port_record(22, "tcp", "ssh", ""),
            80: cantina._port_record(80, "tcp", "http", ""),
            445: cantina._port_record(445, "tcp", "smb", ""),
        }
        replaced = replaced_builtin_services(reg)
        types = {t[0] for t in sc.build_recon_tasks()}
        for s in ("ssh", "http", "smb"):
            if s in replaced:
                assert s not in types
