"""Unit tests for cantina decision-branch helpers (enum-only)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from cantina import (
    HTTP_PORTS,
    actions_to_run,
    decide_ftp_actions,
    decide_http_actions,
    decide_redis_actions,
    decide_smb_actions,
    decide_snmp_actions,
    parse_http_probe,
    select_service_type,
    tool_exists,
    _BANNED_AUTO_TOOLS,
)


class TestParseHttpProbe:
    def test_real_html_app(self):
        headers = "HTTP/1.1 200 OK\r\nServer: nginx/1.18\r\nContent-Type: text/html\r\n\r\n"
        body = "<!DOCTYPE html><html><title>App</title><body>hello world app page content here</body>"
        s = parse_http_probe(headers, body)
        assert s["looks_http"] is True
        assert s["status"] == 200
        assert s["has_html"] is True
        assert s["real_app"] is True
        assert s["tiny_banner"] is False

    def test_tiny_banner_not_real_app(self):
        headers = "HTTP/1.0 200 OK\r\nServer: cantina-obscure/0.1\r\nContent-Length: 12\r\n\r\n"
        body = "hello-obscure"
        s = parse_http_probe(headers, body)
        assert s["looks_http"] is True
        assert s["tiny_banner"] is True
        assert s["real_app"] is False

    def test_not_http(self):
        s = parse_http_probe("SSH-2.0-OpenSSH_8.2", "")
        assert s["looks_http"] is False
        assert s["real_app"] is False

    def test_wordpress_cms(self):
        headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        body = "<html><link href='/wp-content/themes/x.css'></html>" + ("x" * 100)
        s = parse_http_probe(headers, body)
        assert s["cms"] == "wordpress"

    def test_auth_wall_is_real_app(self):
        headers = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nServer: Apache\r\n\r\n"
        s = parse_http_probe(headers, "")
        assert s["real_app"] is True


class TestDecideHttp:
    def test_tiny_banner_skips_heavy(self):
        signals = parse_http_probe(
            "HTTP/1.0 200 OK\r\nServer: fake\r\n\r\n", "hi-banner",
        )
        actions = decide_http_actions(signals, depth="deep", port=4444)
        by = {a["tool"]: a for a in actions}
        assert by["dirbust"]["run"] is False
        assert by["nikto"]["run"] is False
        assert by["whatweb"]["run"] is True

    def test_real_app_deep_runs_heavy(self):
        signals = parse_http_probe(
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n",
            "<html><title>x</title>" + ("body " * 40),
        )
        actions = decide_http_actions(signals, depth="deep", port=80)
        by = {a["tool"]: a for a in actions}
        assert by["dirbust"]["run"] is True
        assert by["nikto"]["run"] is True

    def test_real_app_normal_low_port_skips_nikto(self):
        signals = parse_http_probe(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
            "<html><title>x</title>" + ("y" * 100),
        )
        actions = decide_http_actions(signals, depth="normal", port=5601)
        by = {a["tool"]: a for a in actions}
        assert by["dirbust"]["run"] is True  # real app still dirbusts
        assert by["nikto"]["run"] is False  # not high-value in normal

    def test_wordpress_branch(self):
        signals = parse_http_probe(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
            "<html>wp-content" + ("z" * 100),
        )
        actions = decide_http_actions(signals, depth="normal", port=80)
        by = {a["tool"]: a for a in actions}
        assert by["wpscan"]["run"] is True

    def test_banned_tools_never_selected(self):
        signals = parse_http_probe(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
            "<html>" + ("a" * 100),
        )
        actions = decide_http_actions(signals, depth="deep", port=80)
        names = {a["tool"] for a in actions}
        assert not (names & _BANNED_AUTO_TOOLS)


class TestDecideSmbFtpRedisSnmp:
    def test_smb_null_denied_skips_enum4linux(self):
        actions = decide_smb_actions(
            null_list_ok=False, shares_readable=False, access_denied=True,
        )
        by = {a["tool"]: a for a in actions}
        assert by["enum4linux"]["run"] is False
        assert by["nmap_smb_scripts"]["run"] is True

    def test_smb_null_ok_runs_heavy(self):
        actions = decide_smb_actions(
            null_list_ok=True, shares_readable=False, access_denied=False,
        )
        by = {a["tool"]: a for a in actions}
        assert by["enum4linux"]["run"] is True
        assert by["smbmap"]["run"] is True

    def test_ftp_anon_gates_listing(self):
        no = {a["tool"]: a for a in decide_ftp_actions(anon_allowed=False, has_version=True)}
        yes = {a["tool"]: a for a in decide_ftp_actions(anon_allowed=True, has_version=True)}
        assert no["anon_list"]["run"] is False
        assert yes["anon_list"]["run"] is True

    def test_redis_pong_gates_info(self):
        no = {a["tool"]: a for a in decide_redis_actions(pong=False)}
        yes = {a["tool"]: a for a in decide_redis_actions(pong=True)}
        assert no["redis_info"]["run"] is False
        assert yes["redis_info"]["run"] is True
        assert "redis-brute" not in {a["tool"] for a in yes.values()} or True
        tools = [a["tool"] for a in decide_redis_actions(pong=True)]
        assert "redis-brute" not in tools

    def test_snmp_walk_needs_community(self):
        no = {a["tool"]: a for a in decide_snmp_actions(valid_community=None)}
        yes = {a["tool"]: a for a in decide_snmp_actions(valid_community="public")}
        assert no["snmpwalk_deep"]["run"] is False
        assert yes["snmpwalk_deep"]["run"] is True

    def test_actions_to_run_filters(self):
        actions = [
            {"tool": "whatweb", "run": True},
            {"tool": "nikto", "run": False},
            {"tool": "hydra", "run": True},  # banned
        ]
        ran = actions_to_run(actions)
        names = [a["tool"] for a in ran]
        assert names == ["whatweb"]


class TestSelectServiceTypeCleanup:
    """Regression: full HTTP_PORTS + alt-FTP must dispatch (M1/M2 fixes)."""

    def test_obscure_http_ports_not_none(self):
        for port in (4444, 7001, 5000, 3000, 8080):
            assert select_service_type(port, "unknown", "") == "http", port
            assert port in HTTP_PORTS or port in (3000, 5000, 8080)

    def test_nmap_weird_labels_still_http(self):
        assert select_service_type(4444, "krb524", "") == "http"
        assert select_service_type(7001, "afs3-callback", "") == "http"

    def test_alt_ftp_service_name(self):
        assert select_service_type(2121, "ccproxy-ftp", "") == "ftp"
        assert select_service_type(21, "ftp", "") == "ftp"

    def test_dedicated_services_before_http(self):
        assert select_service_type(5601, "esmagent", "") == "kibana"
        assert select_service_type(9200, "wap-wsp", "") == "elasticsearch"
        assert select_service_type(88, "kerberos", "") == "kerberos"
        assert select_service_type(11211, "memcache", "") == "memcached"

    def test_tool_exists_no_shell_for_missing(self):
        assert tool_exists("this-binary-definitely-missing-xyz-cantina") is False
        # real python interpreter used to run tests is on PATH
        assert tool_exists("python") or tool_exists("python3") or tool_exists("py")
