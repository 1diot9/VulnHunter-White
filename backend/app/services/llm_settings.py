"""LLM Provider / role resolution for recon / worker / reviewer / verifier."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from ..models import AppSettings, Project, SessionLocal
from ..schemas import LlmProviderIn, LlmProviderOut, LlmRoleAssignment, SettingsOut

LlmRole = Literal["recon", "worker", "reviewer", "verifier"]
LLM_ROLES: tuple[LlmRole, ...] = ("recon", "worker", "reviewer", "verifier")
_RECON_AGENT_ROLES = frozenset(
    {"recon", "recon_mark", "recon_old_vuln", "recon_old_vuln_ghsa", "recon_source_ext"}
)
_WIRE = frozenset({"chat", "responses", "anthropic"})
_WIRE_ALIASES = {"messages": "anthropic", "claude": "anthropic"}


def normalize_wire_api(value: str | None) -> str:
    wire = (value or "chat").strip().lower()
    wire = _WIRE_ALIASES.get(wire, wire)
    return wire if wire in _WIRE else "chat"


def normalize_llm_base_url(value: str | None) -> str:
    url = (value or "").strip().rstrip("/")
    if not url:
        return ""
    parsed = urlsplit(url)
    if parsed.netloc.lower() == "open.bigmodel.cn" and parsed.path.rstrip("/") == "/api/v1":
        parsed = parsed._replace(path="/api/paas/v4")
        return urlunsplit(parsed).rstrip("/")
    return url


@dataclass(frozen=True)
class ResolvedLlm:
    base_url: str
    wire_api: str
    model: str
    api_key: str
    source: str


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


def providers_for_api(row: AppSettings | None) -> list[LlmProviderOut]:
    out: list[LlmProviderOut] = []
    for p in load_providers_raw(row):
        pid = str(p.get("id") or "").strip()
        if not pid:
            continue
        wire = normalize_wire_api(str(p.get("wire_api") or "chat"))
        out.append(
            LlmProviderOut(
                id=pid,
                name=str(p.get("name") or pid).strip() or pid,
                base_url=normalize_llm_base_url(str(p.get("base_url") or "")),
                wire_api=wire,
                env_key=str(p.get("env_key") or "OPENAI_API_KEY").strip() or "OPENAI_API_KEY",
                api_key_set=bool(str(p.get("api_key") or "").strip()),
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
    return SettingsOut(
        llm_providers=providers_for_api(row),
        llm_roles=roles_for_api(row),
        llm_thread_limit=max(1, int(getattr(row, "llm_thread_limit", None) or 6)),
        github_pat_set=bool((row.github_pat or "").strip()),
        fofa_key_set=bool((getattr(row, "fofa_key", None) or "").strip()),
        fofa_base_url=(getattr(row, "fofa_base_url", None) or "").strip() or "https://fofa.info",
        default_model=(row.default_model or "").strip(),
        default_base_url=normalize_llm_base_url(row.default_base_url),
        default_api_key_set=bool((row.default_api_key or "").strip()),
        context_window=int(row.context_window or 128000),
        http_proxy=_proxy_for_api(row, "http_proxy", "https_proxy", "http_proxy"),
        chat_proxy=_proxy_for_api(row, "chat_proxy", "chat_proxy"),
        cli_tools_dir=(getattr(row, "cli_tools_dir", None) or "").strip() or "tools/cli",
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
        merged.append(
            {
                "id": pid,
                "name": (item.name or "").strip() or pid,
                "base_url": normalize_llm_base_url(item.base_url),
                "wire_api": wire,
                "env_key": (item.env_key or "").strip()
                or ("ANTHROPIC_API_KEY" if wire == "anthropic" else "OPENAI_API_KEY"),
                "api_key": api_key,
            }
        )
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

    if provider:
        base_url = normalize_llm_base_url(str(provider.get("base_url") or ""))
        api_key = str(provider.get("api_key") or "").strip()
        env_key = str(provider.get("env_key") or "OPENAI_API_KEY").strip()
        if not api_key:
            api_key = (os.environ.get(env_key) or "").strip()
        wire = normalize_wire_api(str(provider.get("wire_api") or "chat"))
        if not api_key and wire == "anthropic":
            api_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
        if not model:
            model = (row.default_model if row else "") or "gpt-4o"
        default_url = "https://api.anthropic.com/v1" if wire == "anthropic" else "https://api.openai.com/v1"
        return ResolvedLlm(
            base_url=base_url.rstrip("/") or default_url,
            wire_api=wire,
            model=model,
            api_key=api_key,
            source=f"provider:{provider_id}" + ("+project" if project_model else ""),
        )

    # Fallback defaults
    base_url = normalize_llm_base_url((row.default_base_url if row else "") or "") or "https://api.openai.com/v1"
    api_key = ((row.default_api_key if row else "") or "").strip() or (os.environ.get("OPENAI_API_KEY") or "")
    model = model or ((row.default_model if row else "") or "").strip() or "gpt-4o"
    return ResolvedLlm(
        base_url=base_url,
        wire_api="chat",
        model=model,
        api_key=api_key,
        source="default" + ("+project" if project_model else ""),
    )


def _saved_provider(row: AppSettings | None) -> dict[str, Any] | None:
    providers = load_providers_raw(row)
    if not providers:
        return None
    for p in providers:
        if str(p.get("id") or "").strip() == "default":
            return p
    return providers[0]


def resolve_probe_target(
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    wire_api: str | None = None,
) -> tuple[str, str, str, str]:
    """Resolve Base URL / API key / model / wire_api from form overrides, then saved settings."""
    row = get_settings_row()
    saved_url = normalize_llm_base_url(row.default_base_url)
    saved_key = (row.default_api_key or "").strip()
    saved_model = (row.default_model or "").strip()
    saved_wire = "chat"
    provider = _saved_provider(row)
    if provider:
        saved_wire = normalize_wire_api(str(provider.get("wire_api") or "chat"))
        if not saved_url:
            saved_url = normalize_llm_base_url(str(provider.get("base_url") or ""))
        if not saved_key:
            saved_key = str(provider.get("api_key") or "").strip()
            if not saved_key:
                env_key = str(provider.get("env_key") or "OPENAI_API_KEY").strip() or "OPENAI_API_KEY"
                saved_key = (os.environ.get(env_key) or "").strip()

    wire = normalize_wire_api(wire_api) if (wire_api or "").strip() else saved_wire
    default_url = "https://api.anthropic.com/v1" if wire == "anthropic" else "https://api.openai.com/v1"
    url = normalize_llm_base_url(base_url) or saved_url or default_url
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
