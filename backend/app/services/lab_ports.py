"""Docker lab host-port conflict detection and compose rewriting."""

from __future__ import annotations

import re
from typing import Iterable

from .docker_service import docker_service

_HOST_PORT_FIELDS = (
    "host_port",
    "jdwp_host_port",
    "inspect_host_port",
    "debugpy_host_port",
)

# Short form: 127.0.0.1:18080:8080 / 18080:8080 / 18080:8080/tcp
_COMPOSE_PORT_SHORT_RE = re.compile(
    r'(?P<pre>["\']?)'
    r"(?:(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):)?"
    r"(?P<host>\d+):(?P<cport>\d+(?:/(?:tcp|udp))?)"
    r'(?P<suf>["\']?)'
)
_COMPOSE_PUBLISHED_RE = re.compile(
    r'(?P<pre>^[ \t]*published:[ \t]*["\']?)(?P<host>\d+)(?P<suf>["\']?[ \t]*(?:#.*)?)?$',
    re.MULTILINE,
)
_PORT_CONFLICT_HINTS = (
    "port is already allocated",
    "address already in use",
    "bind: address already in use",
    "failed to bind host port",
    "listen tcp",
)


def looks_like_port_conflict(message: str) -> bool:
    low = (message or "").lower()
    return any(h in low for h in _PORT_CONFLICT_HINTS)


def extract_compose_host_ports(text: str) -> list[int]:
    """Extract published host ports from compose YAML text."""
    found: list[int] = []
    seen: set[int] = set()
    for match in _COMPOSE_PORT_SHORT_RE.finditer(text or ""):
        port = int(match.group("host"))
        if port not in seen:
            seen.add(port)
            found.append(port)
    for match in _COMPOSE_PUBLISHED_RE.finditer(text or ""):
        port = int(match.group("host"))
        if port not in seen:
            seen.add(port)
            found.append(port)
    return found


def rewrite_compose_host_ports(text: str, mapping: dict[int, int]) -> tuple[str, int]:
    """Replace host ports in compose text; return (new_text, replacement_count)."""
    if not mapping:
        return text, 0
    count = 0

    def _short(match: re.Match[str]) -> str:
        nonlocal count
        old = int(match.group("host"))
        new = mapping.get(old)
        if new is None or new == old:
            return match.group(0)
        count += 1
        ip = match.group("ip")
        ip_part = f"{ip}:" if ip else ""
        return f'{match.group("pre")}{ip_part}{new}:{match.group("cport")}{match.group("suf")}'

    def _published(match: re.Match[str]) -> str:
        nonlocal count
        old = int(match.group("host"))
        new = mapping.get(old)
        if new is None or new == old:
            return match.group(0)
        count += 1
        return f'{match.group("pre")}{new}{match.group("suf") or ""}'

    out = _COMPOSE_PORT_SHORT_RE.sub(_short, text)
    out = _COMPOSE_PUBLISHED_RE.sub(_published, out)
    return out, count


def resolve_host_port_conflicts(
    *,
    host_port: int | None,
    jdwp_host_port: int | None,
    inspect_host_port: int | None,
    debugpy_host_port: int | None,
    extra_ports: Iterable[int] = (),
    force_all: bool = False,
) -> tuple[dict[str, int | None], dict[int, int], list[str]]:
    """Detect conflicts and allocate free ports.

    Returns:
        updated_fields: the four host-port fields (possibly remapped)
        mapping: {old_host_port: new_port} including compose extras
        changes: human-readable change notes
    """
    fields: dict[str, int | None] = {
        "host_port": int(host_port) if host_port is not None else None,
        "jdwp_host_port": int(jdwp_host_port) if jdwp_host_port is not None else None,
        "inspect_host_port": int(inspect_host_port) if inspect_host_port is not None else None,
        "debugpy_host_port": int(debugpy_host_port) if debugpy_host_port is not None else None,
    }

    candidates: list[int] = []
    seen: set[int] = set()
    for value in list(fields.values()) + [int(p) for p in extra_ports]:
        if value is None:
            continue
        port = int(value)
        if port in seen:
            continue
        seen.add(port)
        candidates.append(port)

    to_replace: list[int] = []
    for port in candidates:
        if force_all or docker_service.is_port_in_use(port):
            to_replace.append(port)

    mapping: dict[int, int] = {}
    if to_replace:
        free_ports = docker_service.allocate_free_ports(len(to_replace))
        reserved = set(candidates) - set(to_replace)
        for old, new in zip(to_replace, free_ports):
            while new in reserved or new in mapping.values() or (
                new != old and docker_service.is_port_in_use(new)
            ):
                new = docker_service.find_free_port()
            mapping[old] = new
            reserved.add(new)

    updated = {
        key: (mapping.get(val, val) if val is not None else None)
        for key, val in fields.items()
    }
    changes = [
        f"{key}: {fields[key]} → {updated[key]}"
        for key in _HOST_PORT_FIELDS
        if fields[key] is not None and updated[key] != fields[key]
    ]
    known = {fields[k] for k in _HOST_PORT_FIELDS if fields[k] is not None}
    for old, new in mapping.items():
        if old not in known:
            changes.append(f"compose:{old} → {new}")
    return updated, mapping, changes


def any_host_ports_in_use(
    *,
    host_port: int | None = None,
    jdwp_host_port: int | None = None,
    inspect_host_port: int | None = None,
    debugpy_host_port: int | None = None,
    extra_ports: Iterable[int] = (),
) -> bool:
    """True if any declared host port is busy."""
    ports: list[int] = []
    for value in (
        host_port,
        jdwp_host_port,
        inspect_host_port,
        debugpy_host_port,
        *extra_ports,
    ):
        if value is None or value == "":
            continue
        try:
            ports.append(int(value))
        except (TypeError, ValueError):
            continue
    return any(docker_service.is_port_in_use(p) for p in ports)
