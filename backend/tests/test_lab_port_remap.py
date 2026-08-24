"""Tests for docker lab host-port conflict remapping."""

from __future__ import annotations

from unittest.mock import patch

from app.services.lab_ports import (
    extract_compose_host_ports,
    resolve_host_port_conflicts,
    rewrite_compose_host_ports,
)


def test_extract_and_rewrite_short_form():
    src = (
        "services:\n"
        "  app:\n"
        "    ports:\n"
        '      - "127.0.0.1:18080:8080"\n'
        '      - "127.0.0.1:15005:5005"\n'
        "  db:\n"
        "    ports:\n"
        "      - 13306:3306\n"
    )
    ports = extract_compose_host_ports(src)
    assert ports == [18080, 15005, 13306]

    out, n = rewrite_compose_host_ports(src, {18080: 28080, 15005: 25005, 13306: 23306})
    assert n == 3
    assert '"127.0.0.1:28080:8080"' in out
    assert '"127.0.0.1:25005:5005"' in out
    assert "23306:3306" in out
    assert ":8080" in out
    assert ":5005" in out
    assert ":3306" in out


def test_rewrite_published_long_form():
    src = (
        "services:\n"
        "  app:\n"
        "    ports:\n"
        "      - target: 8080\n"
        "        published: 18080\n"
        "        host_ip: 127.0.0.1\n"
    )
    assert extract_compose_host_ports(src) == [18080]
    out, n = rewrite_compose_host_ports(src, {18080: 19090})
    assert n == 1
    assert "published: 19090" in out
    assert "target: 8080" in out


def test_rewrite_ignores_unrelated_host_port_like_strings():
    src = (
        "services:\n"
        "  app:\n"
        "    environment:\n"
        '      URL: "http://127.0.0.1:18080"\n'
        '      ZK: "zookeeper:2181"\n'
        "    ports:\n"
        '      - "127.0.0.1:18080:8080"\n'
    )
    out, n = rewrite_compose_host_ports(src, {18080: 19090})
    assert n == 1
    assert 'URL: "http://127.0.0.1:18080"' in out
    assert '"127.0.0.1:19090:8080"' in out


@patch("app.services.lab_ports.docker_service")
def test_remaps_only_busy_ports(mock_docker):
    mock_docker.is_port_in_use.side_effect = lambda p, host="127.0.0.1": int(p) in {
        18080,
        13306,
    }
    mock_docker.allocate_free_ports.return_value = [28080, 23306]
    mock_docker.find_free_port.return_value = 29999

    fields, mapping, changes = resolve_host_port_conflicts(
        host_port=18080,
        jdwp_host_port=15005,
        inspect_host_port=None,
        debugpy_host_port=None,
        extra_ports=[13306],
    )
    assert fields["host_port"] == 28080
    assert fields["jdwp_host_port"] == 15005
    assert mapping == {18080: 28080, 13306: 23306}
    assert any("host_port" in c for c in changes)
    assert any("13306" in c for c in changes)


@patch("app.services.lab_ports.docker_service")
def test_force_all_remaps_even_if_free(mock_docker):
    mock_docker.is_port_in_use.return_value = False
    mock_docker.allocate_free_ports.return_value = [30001, 30002]
    mock_docker.find_free_port.return_value = 39999

    fields, mapping, _changes = resolve_host_port_conflicts(
        host_port=18080,
        jdwp_host_port=15005,
        inspect_host_port=None,
        debugpy_host_port=None,
        force_all=True,
    )
    assert fields["host_port"] == 30001
    assert fields["jdwp_host_port"] == 30002
    assert mapping == {18080: 30001, 15005: 30002}
