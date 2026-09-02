"""LLM Provider / role resolution for recon / worker / reviewer / verifier."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from ..models import AppSettings, Project, SessionLocal
from ..config import settings
from ..schemas import (
    LlmPoolEndpointIn,
    LlmPoolEndpointOut,
    LlmProviderIn,
    LlmProviderOut,
    LlmRoleAssignment,
    SettingsOut,
)
from .access_token import is_access_token_configured

LlmRole = Literal["recon", "worker", "reviewer", "verifier"]
LLM_ROLES: tuple[LlmRole, ...] = ("recon", "worker", "reviewer", "verifier")
_RECON_AGENT_ROLES = frozenset(
    {"recon", "recon_mark", "recon_old_vuln", "recon_old_vuln_ghsa", "recon_source_ext"}
)
_WIRE = frozenset({"chat", "responses", "anthropic"})
_WIRE_ALIASES = {"messages": "anthropic", "claude": "anthropic"}
DEFAULT_ENDPOINT_INFLIGHT = 6
_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata.tencentyun.com",
    }
)
_METADATA_IPS = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.169.253"),
        ipaddress.ip_address("169.254.0.23"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


def normalize_wire_api(value: str | None) -> str:
    wire = (value or "chat").strip().lower()
    wire = _WIRE_ALIASES.get(wire, wire)
    return wire if wire in _WIRE else "chat"


def normalize_llm_base_url(value: str | None) -> str:
    url = (value or "").strip()
    if not url:
        return ""
    parsed = urlsplit(url)
    parsed = parsed._replace(fragment="")
    if parsed.netloc.lower() == "open.bigmodel.cn" and parsed.path.rstrip("/") == "/api/v1":
        parsed = parsed._replace(path="/api/paas/v4")
    return urlunsplit(parsed).rstrip("/")


def _literal_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = (host or "").strip().strip("[]")
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        pass
    if text.startswith(("0x", "0X")):
        try:
            return ipaddress.IPv4Address(int(text, 16))
        except ValueError:
            return None
    if text.isdigit():
        try:
            return ipaddress.IPv4Address(int(text, 10))
        except ValueError:
            return None
    return None


def _ip_is_metadata(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_link_local:
        return True
    return ip in _METADATA_IPS


def _host_is_metadata(host: str) -> bool:
    h = (host or "").strip(".").lower()
    if not h:
        return False
    if h in _METADATA_HOSTS or h.endswith(".metadata.google.internal"):
        return True
    ip = _literal_ip(h)
    return ip is not None and _ip_is_metadata(ip)


def assert_safe_llm_base_url(value: str | None) -> str:
    """Allow local LLM (127.0.0.1 / RFC1918); reject non-http(s) and cloud metadata."""
    url = normalize_llm_base_url(value)
    if not url:
        return ""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Base URL 只允许 http 或 https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Base URL 不能包含用户名或密码")
    try:
        host = (parsed.hostname or "").strip().lower()
    except ValueError as exc:
        raise ValueError("Base URL 主机名无效") from exc
    if not host:
        raise ValueError("Base URL 缺少主机名")
    if _host_is_metadata(host):
        raise ValueError("Base URL 不能指向云元数据地址")
    return url


@dataclass(frozen=True)
class ResolvedLlm:
    base_url: str
    wire_api: str
    model: str
    api_key: str
    source: str
    endpoint_id: str = ""


@dataclass(frozen=True)
class PoolEndpoint:
    id: str
    base_url: str
    api_key: str
    model: str = ""
    max_inflight: int = DEFAULT_ENDPOINT_INFLIGHT


def _parse_json(raw: str | None, default: Any) -> Any:
    text = (raw or "").strip()
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return default


def load_providers_raw(row: AppSettings | None) -> list[dict[str, Any]]:
    data = _parse_json(getattr(row, "llm_providers", None) if row else None, [])
    if not isinstance(data, list):
        return []
    return [p for p in data if isinstance(p, dict)]


def load_roles_raw(row: AppSettings | None) -> dict[str, Any]:
    data = _parse_json(getattr(row, "llm_roles", None) if row else None, {})
    if not isinstance(data, dict):
        return {}
    return data


def _clamp_inflight(value: Any, *, default: int = DEFAULT_ENDPOINT_INFLIGHT) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = default
    return max(1, n)


def _new_endpoint_id(used: set[str], index: int) -> str:
    for i in range(index, index + 1000):
        eid = f"ep-{i}"
        if eid not in used:
            return eid
    return f"ep-{index}-{len(used)}"


def _normalize_endpoint_dicts(
    raw_list: list[Any],
    *,
    fallback_url: str = "",
    fallback_key: str = "",
    fallback_inflight: int = DEFAULT_ENDPOINT_INFLIGHT,
) -> list[dict[str, Any]]:
    """Normalize endpoint dicts; synthesize one from legacy fields when empty."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, item in enumerate(raw_list or []):
        if not isinstance(item, dict):
            continue
        eid = str(item.get("id") or "").strip() or _new_endpoint_id(seen, idx + 1)
        if eid in seen:
            eid = _new_endpoint_id(seen, idx + 1)
        seen.add(eid)
        url = normalize_llm_base_url(str(item.get("base_url") or ""))
        key = str(item.get("api_key") or "").strip()
        model = str(item.get("model") or "").strip()
        out.append(
            {
                "id": eid,
                "base_url": url,
                "api_key": key,
                "model": model,
                "max_inflight": _clamp_inflight(item.get("max_inflight")),
            }
        )
    if out:
        return out
    url = normalize_llm_base_url(fallback_url)
    if not url and not fallback_key:
        return [
            {
                "id": "ep-1",
                "base_url": "",
                "api_key": "",
                "model": "",
                "max_inflight": _clamp_inflight(fallback_inflight),
            }
        ]
    return [
        {
            "id": "ep-1",
            "base_url": url,
            "api_key": (fallback_key or "").strip(),
            "model": "",
            "max_inflight": _clamp_inflight(fallback_inflight),
        }
    ]


def endpoints_from_provider(
    provider: dict[str, Any] | None,
    *,
    fallback_url: str = "",
    fallback_key: str = "",
    fallback_inflight: int = DEFAULT_ENDPOINT_INFLIGHT,
) -> list[dict[str, Any]]:
    raw = (provider or {}).get("endpoints") if provider else None
    raw_list = raw if isinstance(raw, list) else []
    base_url = str((provider or {}).get("base_url") or "") or fallback_url
    api_key = str((provider or {}).get("api_key") or "") or fallback_key
    return _normalize_endpoint_dicts(
        raw_list,
        fallback_url=base_url,
        fallback_key=api_key,
        fallback_inflight=fallback_inflight,
    )


def load_pool_endpoints_raw(row: AppSettings | None) -> list[dict[str, Any]]:
    """Load endpoint pool from default provider, synthesizing from legacy fields."""
    provider = _saved_provider(row)
    thread_limit = max(1, int(getattr(row, "llm_thread_limit", None) or DEFAULT_ENDPOINT_INFLIGHT)) if row else DEFAULT_ENDPOINT_INFLIGHT
    fallback_url = normalize_llm_base_url(getattr(row, "default_base_url", None) if row else "")
    fallback_key = ((getattr(row, "default_api_key", None) if row else "") or "").strip()
    return endpoints_from_provider(
        provider,
        fallback_url=fallback_url,
        fallback_key=fallback_key,
        fallback_inflight=thread_limit,
    )


def endpoints_for_api(row: AppSettings | None) -> list[LlmPoolEndpointOut]:
    return [
        LlmPoolEndpointOut(
            id=str(ep.get("id") or ""),
            base_url=normalize_llm_base_url(str(ep.get("base_url") or "")),
            api_key_set=bool(str(ep.get("api_key") or "").strip()),
            model=str(ep.get("model") or "").strip(),
            max_inflight=_clamp_inflight(ep.get("max_inflight")),
        )
        for ep in load_pool_endpoints_raw(row)
    ]


def pool_endpoints_resolved(row: AppSettings | None = None) -> list[PoolEndpoint]:
    """Runtime pool: resolved keys with env fallback for empty endpoint keys."""
    if row is None:
        row = get_settings_row()
    provider = _saved_provider(row)
    wire = normalize_wire_api(str((provider or {}).get("wire_api") or "chat"))
    env_key = str((provider or {}).get("env_key") or "OPENAI_API_KEY").strip() or "OPENAI_API_KEY"
    pool_fallback = ""
    for ep in load_pool_endpoints_raw(row):
        key = str(ep.get("api_key") or "").strip()
        if key:
            pool_fallback = key
            break
    if not pool_fallback:
        pool_fallback = ((getattr(row, "default_api_key", None) or "") or "").strip()
    if not pool_fallback:
        pool_fallback = (os.environ.get(env_key) or "").strip()
    if not pool_fallback and wire == "anthropic":
        pool_fallback = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()

    out: list[PoolEndpoint] = []
    for ep in load_pool_endpoints_raw(row):
        url = normalize_llm_base_url(str(ep.get("base_url") or ""))
        if not url:
            continue
        key = str(ep.get("api_key") or "").strip() or pool_fallback
        out.append(
            PoolEndpoint(
                id=str(ep.get("id") or ""),
                base_url=url,
                api_key=key,
                model=str(ep.get("model") or "").strip(),
                max_inflight=_clamp_inflight(ep.get("max_inflight")),
            )
        )
    return out


def merge_endpoints_update(
    existing: list[dict[str, Any]],
    incoming: list[LlmPoolEndpointIn],
) -> list[dict[str, Any]]:
    old_by_id = {
        str(ep.get("id") or "").strip(): ep
        for ep in existing
        if str(ep.get("id") or "").strip()
    }
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for idx, item in enumerate(incoming):
        eid = (item.id or "").strip() or _new_endpoint_id(seen, idx + 1)
        if eid in seen:
            raise ValueError(f"重复的端点 id: {eid}")
        seen.add(eid)
        prev = old_by_id.get(eid) or {}
        if item.api_key is None:
            api_key = str(prev.get("api_key") or "")
        else:
            api_key = item.api_key.strip()
        url = assert_safe_llm_base_url(item.base_url)
        if not url:
            raise ValueError(f"端点 {eid}: Base URL 不能为空")
        merged.append(
            {
                "id": eid,
                "base_url": url,
                "api_key": api_key,
                "model": (item.model or "").strip(),
                "max_inflight": _clamp_inflight(item.max_inflight),
            }
        )
    if not merged:
        raise ValueError("至少保留一个 Base URL 端点")
    return merged


def apply_endpoints_to_settings_row(
    row: AppSettings,
    endpoints: list[dict[str, Any]],
    *,
    wire_api: str | None = None,
) -> None:
    """Write endpoints into default provider + sync legacy default_* / thread limit."""
    providers = load_providers_raw(row)
    provider = None
    for p in providers:
        if str(p.get("id") or "").strip() == "default":
            provider = p
            break
    if provider is None and providers:
        provider = providers[0]
    if provider is None:
        provider = {
            "id": "default",
            "name": "Default",
            "base_url": "",
            "wire_api": "chat",
            "env_key": "OPENAI_API_KEY",
            "api_key": "",
        }
        providers = [provider]
    elif provider not in providers:
        providers = [provider] + [p for p in providers if p is not provider]

    wire = normalize_wire_api(wire_api or str(provider.get("wire_api") or "chat"))
    first = endpoints[0]
    provider["base_url"] = str(first.get("base_url") or "")
    provider["api_key"] = str(first.get("api_key") or "")
    provider["wire_api"] = wire
    provider["env_key"] = str(provider.get("env_key") or "").strip() or (
        "ANTHROPIC_API_KEY" if wire == "anthropic" else "OPENAI_API_KEY"
    )
    provider["endpoints"] = endpoints
    # Keep default provider first
    others = [p for p in providers if str(p.get("id") or "").strip() != str(provider.get("id") or "")]
    row.llm_providers = json.dumps([provider] + others, ensure_ascii=False)
    row.default_base_url = str(first.get("base_url") or "") or None
    first_key = str(first.get("api_key") or "").strip()
    if first_key:
        row.default_api_key = first_key
    first_model = str(first.get("model") or "").strip()
    if first_model and not (row.default_model or "").strip():
        row.default_model = first_model
    row.llm_thread_limit = max(1, sum(_clamp_inflight(ep.get("max_inflight")) for ep in endpoints))


def scale_single_endpoint_inflight(row: AppSettings, thread_limit: int) -> bool:
    """If pool has a single endpoint, update its max_inflight from legacy llm_thread_limit."""
    endpoints = load_pool_endpoints_raw(row)
    if len(endpoints) != 1:
        return False
    endpoints[0]["max_inflight"] = _clamp_inflight(thread_limit)
    apply_endpoints_to_settings_row(row, endpoints)
    return True


def providers_for_api(row: AppSettings | None) -> list[LlmProviderOut]:
    out: list[LlmProviderOut] = []
    thread_limit = max(1, int(getattr(row, "llm_thread_limit", None) or DEFAULT_ENDPOINT_INFLIGHT)) if row else DEFAULT_ENDPOINT_INFLIGHT
    for p in load_providers_raw(row):
        pid = str(p.get("id") or "").strip()
        if not pid:
            continue
        wire = normalize_wire_api(str(p.get("wire_api") or "chat"))
        eps = endpoints_from_provider(
            p,
            fallback_url=str(p.get("base_url") or ""),
            fallback_key=str(p.get("api_key") or ""),
            fallback_inflight=thread_limit if pid == "default" else DEFAULT_ENDPOINT_INFLIGHT,
        )
        out.append(
            LlmProviderOut(
                id=pid,
                name=str(p.get("name") or pid).strip() or pid,
                base_url=normalize_llm_base_url(str(p.get("base_url") or "")),
                wire_api=wire,
                env_key=str(p.get("env_key") or "OPENAI_API_KEY").strip() or "OPENAI_API_KEY",
                api_key_set=bool(str(p.get("api_key") or "").strip())
                or any(bool(str(ep.get("api_key") or "").strip()) for ep in eps),
                endpoints=[
                    LlmPoolEndpointOut(
                        id=str(ep.get("id") or ""),
                        base_url=normalize_llm_base_url(str(ep.get("base_url") or "")),
                        api_key_set=bool(str(ep.get("api_key") or "").strip()),
                        model=str(ep.get("model") or "").strip(),
                        max_inflight=_clamp_inflight(ep.get("max_inflight")),
                    )
                    for ep in eps
                ],
            )
        )
    return out


def roles_for_api(row: AppSettings | None) -> dict[str, LlmRoleAssignment]:
    raw = load_roles_raw(row)
    out: dict[str, LlmRoleAssignment] = {}
    for role in LLM_ROLES:
        item = raw.get(role)
        if isinstance(item, dict):
            out[role] = LlmRoleAssignment(
                provider_id=str(item.get("provider_id") or "").strip(),
                model=str(item.get("model") or "").strip(),
                reasoning_effort=str(item.get("reasoning_effort") or "").strip(),
            )
        else:
            out[role] = LlmRoleAssignment()
    return out


def _proxy_for_api(row: AppSettings, field: str, *env_attrs: str) -> str:
    stored = getattr(row, field, None)
    if stored is not None:
        return str(stored).strip()
    from ..config import settings as app_settings

    for attr in env_attrs:
        val = (getattr(app_settings, attr, None) or "").strip()
        if val:
            return val
    return ""


def settings_out_from_row(row: AppSettings) -> SettingsOut:
    endpoints = endpoints_for_api(row)
    thread_limit = max(1, sum(ep.max_inflight for ep in endpoints)) if endpoints else max(
        1, int(getattr(row, "llm_thread_limit", None) or 6)
    )
    return SettingsOut(
        llm_providers=providers_for_api(row),
        llm_roles=roles_for_api(row),
        llm_endpoints=endpoints,
        llm_thread_limit=thread_limit,
        github_pat_set=bool((row.github_pat or "").strip()),
        fofa_key_set=bool((getattr(row, "fofa_key", None) or "").strip()),
        fofa_base_url=(getattr(row, "fofa_base_url", None) or "").strip() or "https://fofa.info",
        default_model=(row.default_model or "").strip(),
        default_base_url=normalize_llm_base_url(row.default_base_url)
        or (endpoints[0].base_url if endpoints else ""),
        default_api_key_set=bool((row.default_api_key or "").strip())
        or any(ep.api_key_set for ep in endpoints),
        context_window=int(row.context_window or 128000),
        http_proxy=_proxy_for_api(row, "http_proxy", "https_proxy", "http_proxy"),
        chat_proxy=_proxy_for_api(row, "chat_proxy", "chat_proxy"),
        cli_tools_dir=(getattr(row, "cli_tools_dir", None) or "").strip() or "tools/cli",
        jadx_path=(getattr(row, "jadx_path", None) or "").strip()
        or (getattr(settings, "jadx_path", None) or "").strip(),
        codegraph_path=(getattr(row, "codegraph_path", None) or "").strip()
        or (getattr(settings, "codegraph_path", None) or "").strip(),
        access_token_set=is_access_token_configured(row),
    )


def merge_providers_update(
    existing_raw: list[dict[str, Any]],
    incoming: list[LlmProviderIn],
) -> list[dict[str, Any]]:
    old_by_id = {
        str(p.get("id") or "").strip(): p
        for p in existing_raw
        if str(p.get("id") or "").strip()
    }
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in incoming:
        pid = (item.id or "").strip()
        if not pid:
            raise ValueError("Provider id 不能为空")
        if pid in seen:
            raise ValueError(f"重复的 Provider id: {pid}")
        seen.add(pid)
        wire = normalize_wire_api(item.wire_api)
        raw_wire = (item.wire_api or "chat").strip().lower()
        if raw_wire and raw_wire not in _WIRE and raw_wire not in _WIRE_ALIASES:
            raise ValueError(f"Provider {pid}: wire_api 须为 chat、responses 或 anthropic")
        prev = old_by_id.get(pid) or {}
        if item.api_key is None:
            api_key = str(prev.get("api_key") or "")
        else:
            api_key = item.api_key.strip()
        entry: dict[str, Any] = {
            "id": pid,
            "name": (item.name or "").strip() or pid,
            "base_url": assert_safe_llm_base_url(item.base_url),
            "wire_api": wire,
            "env_key": (item.env_key or "").strip()
            or ("ANTHROPIC_API_KEY" if wire == "anthropic" else "OPENAI_API_KEY"),
            "api_key": api_key,
        }
        if item.endpoints is not None:
            prev_eps = endpoints_from_provider(prev, fallback_url=str(prev.get("base_url") or ""), fallback_key=str(prev.get("api_key") or ""))
            entry["endpoints"] = merge_endpoints_update(prev_eps, item.endpoints)
            if entry["endpoints"]:
                entry["base_url"] = str(entry["endpoints"][0].get("base_url") or entry["base_url"])
                if not entry["api_key"]:
                    entry["api_key"] = str(entry["endpoints"][0].get("api_key") or "")
        elif isinstance(prev.get("endpoints"), list) and prev.get("endpoints"):
            entry["endpoints"] = _normalize_endpoint_dicts(
                prev["endpoints"],
                fallback_url=entry["base_url"],
                fallback_key=entry["api_key"],
            )
        merged.append(entry)
    return merged


def normalize_project_llm_model(value: str | None) -> str | None:
    text = (value or "").strip()
    return text or None


def llm_role_for_agent(role: str) -> LlmRole:
    """Map agent/session roles onto configured LLM slots (recon / worker / reviewer)."""
    r = (role or "").strip().replace("-", "_")
    if r in _RECON_AGENT_ROLES:
        return "recon"
    if r in ("cli_indexer", "cli-indexer"):
        return "reviewer"
    if r == "reviewer" or r.startswith("reviewer_"):
        return "reviewer"
    if r == "verifier":
        return "verifier"
    if r in ("attack_chain", "attack-chain"):
        # Post-review reasoning; reuse reviewer slot (no separate settings UI).
        return "reviewer"
    return "worker"


def resolve_llm(role: LlmRole = "worker", *, project_id: int | None = None) -> ResolvedLlm:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        project_model = None
        if project_id:
            proj = db.get(Project, project_id)
            project_model = normalize_project_llm_model(
                getattr(proj, "llm_model", None) if proj else None
            )
    providers = load_providers_raw(row)
    roles = load_roles_raw(row)
    assignment = roles.get(role) if isinstance(roles.get(role), dict) else {}
    provider_id = str((assignment or {}).get("provider_id") or "").strip()
    model = project_model or str((assignment or {}).get("model") or "").strip()

    provider: dict[str, Any] | None = None
    if provider_id:
        for p in providers:
            if str(p.get("id") or "").strip() == provider_id:
                provider = p
                break

    pool = pool_endpoints_resolved(row)
    if provider:
        wire = normalize_wire_api(str(provider.get("wire_api") or "chat"))
        if not model:
            model = (row.default_model if row else "") or "gpt-4o"
        default_url = "https://api.anthropic.com/v1" if wire == "anthropic" else "https://api.openai.com/v1"
        if pool:
            first = pool[0]
            return ResolvedLlm(
                base_url=first.base_url,
                wire_api=wire,
                model=model,
                api_key=first.api_key,
                source=f"provider:{provider_id}" + ("+project" if project_model else ""),
                endpoint_id=first.id,
            )
        base_url = assert_safe_llm_base_url(str(provider.get("base_url") or ""))
        api_key = str(provider.get("api_key") or "").strip()
        env_key = str(provider.get("env_key") or "OPENAI_API_KEY").strip()
        if not api_key:
            api_key = (os.environ.get(env_key) or "").strip()
        if not api_key and wire == "anthropic":
            api_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
        return ResolvedLlm(
            base_url=base_url.rstrip("/") or default_url,
            wire_api=wire,
            model=model,
            api_key=api_key,
            source=f"provider:{provider_id}" + ("+project" if project_model else ""),
        )

    # Fallback defaults
    if pool:
        first = pool[0]
        model = model or ((row.default_model if row else "") or "").strip() or "gpt-4o"
        return ResolvedLlm(
            base_url=first.base_url,
            wire_api="chat",
            model=model,
            api_key=first.api_key,
            source="default" + ("+project" if project_model else ""),
            endpoint_id=first.id,
        )
    base_url = (
        assert_safe_llm_base_url((row.default_base_url if row else "") or "")
        or "https://api.openai.com/v1"
    )
    api_key = ((row.default_api_key if row else "") or "").strip() or (os.environ.get("OPENAI_API_KEY") or "")
    model = model or ((row.default_model if row else "") or "").strip() or "gpt-4o"
    return ResolvedLlm(
        base_url=base_url,
        wire_api="chat",
        model=model,
        api_key=api_key,
        source="default" + ("+project" if project_model else ""),
    )


def bind_llm_to_endpoint(llm: ResolvedLlm, endpoint: PoolEndpoint) -> ResolvedLlm:
    """Apply endpoint URL/key/model. Project-level model (+project) wins over endpoint model."""
    if "+project" in (llm.source or ""):
        model = llm.model
    else:
        model = (endpoint.model or "").strip() or llm.model
    return ResolvedLlm(
        base_url=endpoint.base_url,
        wire_api=llm.wire_api,
        model=model,
        api_key=endpoint.api_key,
        source=llm.source,
        endpoint_id=endpoint.id,
    )


def _saved_provider(row: AppSettings | None) -> dict[str, Any] | None:
    providers = load_providers_raw(row)
    if not providers:
        return None
    for p in providers:
        if str(p.get("id") or "").strip() == "default":
            return p
    return providers[0]


def _match_pool_endpoint(
    pool: list[dict[str, Any]],
    *,
    endpoint_id: str | None = None,
    base_url: str | None = None,
) -> dict[str, Any] | None:
    """Pick a saved pool endpoint by id, then by normalized Base URL."""
    eid = (endpoint_id or "").strip()
    if eid:
        for ep in pool:
            if str(ep.get("id") or "").strip() == eid:
                return ep
    url = normalize_llm_base_url(base_url)
    if url:
        for ep in pool:
            if normalize_llm_base_url(str(ep.get("base_url") or "")) == url:
                return ep
    return None


def resolve_probe_target(
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    wire_api: str | None = None,
    endpoint_id: str | None = None,
) -> tuple[str, str, str, str]:
    """Resolve Base URL / API key / model / wire_api from form overrides, then saved settings."""
    row = get_settings_row()
    saved_url = normalize_llm_base_url(row.default_base_url)
    saved_key = (row.default_api_key or "").strip()
    saved_model = (row.default_model or "").strip()
    saved_wire = "chat"
    provider = _saved_provider(row)
    pool = load_pool_endpoints_raw(row)
    if provider:
        saved_wire = normalize_wire_api(str(provider.get("wire_api") or "chat"))
        if not saved_url:
            saved_url = normalize_llm_base_url(str(provider.get("base_url") or ""))
        if not saved_key:
            saved_key = str(provider.get("api_key") or "").strip()
            if not saved_key:
                env_key = str(provider.get("env_key") or "OPENAI_API_KEY").strip() or "OPENAI_API_KEY"
                saved_key = (os.environ.get(env_key) or "").strip()
        # Prefer first pool endpoint key/url when present
        for ep in pool:
            if not saved_url and ep.get("base_url"):
                saved_url = normalize_llm_base_url(str(ep.get("base_url") or ""))
            if not saved_key and ep.get("api_key"):
                saved_key = str(ep.get("api_key") or "").strip()
            if saved_url and saved_key:
                break

    matched = _match_pool_endpoint(pool, endpoint_id=endpoint_id, base_url=base_url)
    if matched is not None:
        ep_url = normalize_llm_base_url(str(matched.get("base_url") or ""))
        ep_key = str(matched.get("api_key") or "").strip()
        ep_model = str(matched.get("model") or "").strip()
        if ep_url:
            saved_url = ep_url
        if ep_key:
            saved_key = ep_key
        if ep_model:
            saved_model = ep_model

    wire = normalize_wire_api(wire_api) if (wire_api or "").strip() else saved_wire
    default_url = "https://api.anthropic.com/v1" if wire == "anthropic" else "https://api.openai.com/v1"
    url = assert_safe_llm_base_url(normalize_llm_base_url(base_url) or saved_url or default_url)
    key = (api_key or "").strip() or saved_key or (os.environ.get("OPENAI_API_KEY") or "").strip()
    if not key and wire == "anthropic":
        key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
    mdl = (model or "").strip() or saved_model
    return url, key, mdl, wire


def get_settings_row() -> AppSettings:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row is None:
            row = AppSettings()
            db.add(row)
            db.commit()
            db.refresh(row)
        # detach
        db.expunge(row)
        return row
