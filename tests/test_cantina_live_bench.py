"""Unit tests for cantina_live_bench ground-truth coverage."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
EXPECTED = TOOLS / "lab" / "cantina_lab_expected.json"


@pytest.fixture
def expected():
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


def test_expected_file_exists():
    assert EXPECTED.is_file()
    data = json.loads(EXPECTED.read_text(encoding="utf-8"))
    assert "tcp_expected" in data
    assert len(data["tcp_expected"]) >= 20
    assert any(m.get("tier") == "obscure" for m in data["tcp_expected"].values())


def test_full_tcp_recall(expected):
    from cantina_live_bench import coverage_against_expected

    ports = {
        int(p): {
            "port": int(p),
            "proto": "tcp",
            "service": (meta or {}).get("service", ""),
            "version": "test",
        }
        for p, meta in expected["tcp_expected"].items()
    }
    cov = coverage_against_expected(ports, expected)
    assert cov["recall_tcp"] == 1.0
    assert cov["recall_obscure"] == 1.0
    assert cov["tcp_miss"] == []
    assert cov["obscure_miss"] == []


def test_partial_miss_lowers_weighted(expected):
    from cantina_live_bench import coverage_against_expected

    # Only common ports — obscure miss should drop weighted coverage
    ports = {}
    for p, meta in expected["tcp_expected"].items():
        if (meta or {}).get("tier") == "common":
            ports[int(p)] = {
                "port": int(p),
                "proto": "tcp",
                "service": meta.get("service", ""),
                "version": "",
            }
    cov = coverage_against_expected(ports, expected)
    assert cov["recall_obscure"] < 1.0
    assert cov["weighted_coverage"] < 100.0
    assert len(cov["obscure_miss"]) > 0


def test_udp_recall(expected):
    from cantina_live_bench import coverage_against_expected

    ports = {
        53: {"port": 53, "proto": "udp", "service": "domain", "version": ""},
        137: {"port": 137, "proto": "udp", "service": "netbios-ns", "version": ""},
        161: {"port": 161, "proto": "udp", "service": "snmp", "version": ""},
    }
    # plus one tcp so dict not empty-only
    ports[22] = {"port": 22, "proto": "tcp", "service": "ssh", "version": ""}
    cov = coverage_against_expected(ports, expected)
    assert cov["recall_udp"] == 1.0
    assert cov["udp_miss"] == []
