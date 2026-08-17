"""LLM Provider / role resolution for recon / worker / reviewer."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Literal

from ..models import AppSettings, SessionLocal
from ..schemas import LlmProviderIn, LlmProviderOut, LlmRoleAssignment, SettingsOut

LlmRole = Literal["recon", "worker", "reviewer"]
LLM_ROLES: tuple[LlmRole, ...] = ("recon", "worker", "reviewer")
_RECON_AGENT_ROLES = frozenset({"recon", "recon_mark", "recon_old_vuln", "recon_source_ext"})
_WIRE = frozenset({"chat", "responses"})


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
        wire = str(p.get("wire_api") or "chat").strip().lower()
        if wire not in _WIRE:
            wire = "chat"
        out.append(
            LlmProviderOut(
                id=pid,
                name=str(p.get("name") or pid).strip() or pid,
                base_url=str(p.get("base_url") or "").strip(),
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


def settings_out_from_row(row: AppSettings) -> SettingsOut:
    return SettingsOut(
        llm_providers=providers_for_api(row),
        llm_roles=roles_for_api(row),
        worker_concurrency=int(row.worker_concurrency or 1),
        fix_concurrency=int(getattr(row, "fix_concurrency", None) or 1),
        github_pat_set=bool((row.github_pat or "").strip()),
        default_model=(row.default_model or "").strip(),
        default_base_url=(row.default_base_url or "").strip(),
        default_api_key_set=bool((row.default_api_key or "").strip()),
        context_window=int(row.context_window or 128000),
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
        wire = (item.wire_api or "chat").strip().lower()
        if wire not in _WIRE:
            raise ValueError(f"Provider {pid}: wire_api 须为 chat 或 responses")
        prev = old_by_id.get(pid) or {}
        if item.api_key is None:
            api_key = str(prev.get("api_key") or "")
        else:
            api_key = item.api_key.strip()
        merged.append(
            {
                "id": pid,
                "name": (item.name or "").strip() or pid,
                "base_url": (item.base_url or "").strip(),
                "wire_api": wire,
                "env_key": (item.env_key or "").strip() or "OPENAI_API_KEY",
                "api_key": api_key,
            }
        )
    return merged


def llm_role_for_agent(role: str) -> LlmRole:
    """Map agent/session roles onto configured LLM slots (recon / worker / reviewer)."""
    r = (role or "").strip().replace("-", "_")
    if r in _RECON_AGENT_ROLES:
        return "recon"
    if r == "reviewer":
        return "reviewer"
    return "worker"


def resolve_llm(role: LlmRole = "worker") -> ResolvedLlm:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
    providers = load_providers_raw(row)
    roles = load_roles_raw(row)
    assignment = roles.get(role) if isinstance(roles.get(role), dict) else {}
    provider_id = str((assignment or {}).get("provider_id") or "").strip()
    model = str((assignment or {}).get("model") or "").strip()

    provider: dict[str, Any] | None = None
    if provider_id:
        for p in providers:
            if str(p.get("id") or "").strip() == provider_id:
                provider = p
                break

    if provider:
        base_url = str(provider.get("base_url") or "").strip()
        api_key = str(provider.get("api_key") or "").strip()
        env_key = str(provider.get("env_key") or "OPENAI_API_KEY").strip()
        if not api_key:
            api_key = (os.environ.get(env_key) or "").strip()
        wire = str(provider.get("wire_api") or "chat").strip().lower()
        if not model:
            model = (row.default_model if row else "") or "gpt-4o"
        return ResolvedLlm(
            base_url=base_url.rstrip("/") or "https://api.openai.com/v1",
            wire_api=wire if wire in _WIRE else "chat",
            model=model,
            api_key=api_key,
            source=f"provider:{provider_id}",
        )

    # Fallback defaults
    base_url = ((row.default_base_url if row else "") or "").strip() or "https://api.openai.com/v1"
    api_key = ((row.default_api_key if row else "") or "").strip() or (os.environ.get("OPENAI_API_KEY") or "")
    model = model or ((row.default_model if row else "") or "").strip() or "gpt-4o"
    return ResolvedLlm(
        base_url=base_url.rstrip("/"),
        wire_api="chat",
        model=model,
        api_key=api_key,
        source="default",
    )


def resolve_probe_target(
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> tuple[str, str, str]:
    """Resolve Base URL / API key / model from form overrides, then saved settings."""
    row = get_settings_row()
    saved_url = (row.default_base_url or "").strip()
    saved_key = (row.default_api_key or "").strip()
    saved_model = (row.default_model or "").strip()

    if not saved_url or not saved_key:
        providers = load_providers_raw(row)
        if providers:
            p = providers[0]
            if not saved_url:
                saved_url = str(p.get("base_url") or "").strip()
            if not saved_key:
                saved_key = str(p.get("api_key") or "").strip()
                if not saved_key:
                    env_key = str(p.get("env_key") or "OPENAI_API_KEY").strip() or "OPENAI_API_KEY"
                    saved_key = (os.environ.get(env_key) or "").strip()

    url = (base_url or "").strip() or saved_url or "https://api.openai.com/v1"
    key = (api_key or "").strip() or saved_key or (os.environ.get("OPENAI_API_KEY") or "").strip()
    mdl = (model or "").strip() or saved_model
    return url.rstrip("/"), key, mdl


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
