from __future__ import annotations

import json

from fastapi import APIRouter

from ..models import AppSettings, SessionLocal
from ..schemas import FofaProbeIn, FofaTestOut, LlmModelListOut, LlmProbeIn, LlmTestOut, SettingsOut, SettingsUpdate
from ..services.fofa import test_connectivity as test_fofa_connectivity
from ..services.llm_probe import list_models, test_connectivity
from ..services.llm_settings import (
    load_providers_raw,
    merge_providers_update,
    settings_out_from_row,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("", response_model=SettingsOut)
def get_settings() -> SettingsOut:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row is None:
            row = AppSettings()
            db.add(row)
            db.commit()
            db.refresh(row)
        return settings_out_from_row(row)


@router.put("", response_model=SettingsOut)
def update_settings(body: SettingsUpdate) -> SettingsOut:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row is None:
            row = AppSettings()
            db.add(row)
            db.flush()
        if body.llm_providers is not None:
            merged = merge_providers_update(load_providers_raw(row), body.llm_providers)
            row.llm_providers = json.dumps(merged, ensure_ascii=False)
        if body.llm_roles is not None:
            row.llm_roles = json.dumps(
                {k: v.model_dump() for k, v in body.llm_roles.items()},
                ensure_ascii=False,
            )
        if body.llm_thread_limit is not None:
            row.llm_thread_limit = max(1, int(body.llm_thread_limit))
        if body.github_pat is not None:
            row.github_pat = body.github_pat
        if body.fofa_key is not None:
            row.fofa_key = body.fofa_key
        if body.fofa_base_url is not None:
            row.fofa_base_url = (body.fofa_base_url or "").strip() or None
        if body.default_model is not None:
            row.default_model = body.default_model
        if body.default_base_url is not None:
            row.default_base_url = body.default_base_url
        if body.default_api_key is not None:
            row.default_api_key = body.default_api_key
        if body.context_window is not None:
            row.context_window = int(body.context_window)
        db.commit()
        db.refresh(row)
        out = settings_out_from_row(row)
    from ..services.llm_thread import llm_thread_limiter

    llm_thread_limiter.refresh_limit(out.llm_thread_limit)
    return out


@router.post("/llm/models", response_model=LlmModelListOut)
def probe_llm_models(body: LlmProbeIn) -> LlmModelListOut:
    return list_models(body)


@router.post("/llm/test", response_model=LlmTestOut)
def probe_llm_test(body: LlmProbeIn) -> LlmTestOut:
    return test_connectivity(body)


@router.post("/fofa/test", response_model=FofaTestOut)
def probe_fofa_test(body: FofaProbeIn) -> FofaTestOut:
    return test_fofa_connectivity(body)
