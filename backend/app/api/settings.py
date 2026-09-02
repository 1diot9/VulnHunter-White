from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from ..models import AppSettings, CustomAuditMode, SessionLocal
from ..schemas import (
    AccessTokenUpdate,
    BuiltinAuditModeOut,
    CustomAuditModeCreate,
    CustomAuditModeOut,
    CustomAuditModeUpdate,
    FofaProbeIn,
    FofaTestOut,
    GithubProbeIn,
    GithubTestOut,
    CodegraphProbeIn,
    CodegraphTestOut,
    JadxProbeIn,
    JadxTestOut,
    LiveLogPurgeIn,
    LiveLogPurgeOut,
    LlmEndpointUsageOut,
    LlmModelListOut,
    LlmProbeIn,
    LlmTestOut,
    LlmThreadUsageOut,
    SettingsOut,
    SettingsUpdate,
)
from ..services import custom_audit_modes as cam
from ..services.fofa import test_connectivity as test_fofa_connectivity
from ..services.github_probe import test_connectivity as test_github_connectivity
from ..services.llm_probe import list_models, test_connectivity
from ..services.access_token import update_access_token_hash
from ..services.llm_settings import (
    apply_endpoints_to_settings_row,
    assert_safe_llm_base_url,
    load_pool_endpoints_raw,
    load_providers_raw,
    merge_endpoints_update,
    merge_providers_update,
    scale_single_endpoint_inflight,
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
        try:
            if body.llm_endpoints is not None:
                existing = load_pool_endpoints_raw(row)
                merged_eps = merge_endpoints_update(existing, body.llm_endpoints)
                wire = None
                if body.llm_providers:
                    for p in body.llm_providers:
                        if (p.id or "").strip() == "default":
                            wire = p.wire_api
                            break
                apply_endpoints_to_settings_row(row, merged_eps, wire_api=wire)
            elif body.llm_providers is not None:
                merged = merge_providers_update(load_providers_raw(row), body.llm_providers)
                row.llm_providers = json.dumps(merged, ensure_ascii=False)
                # Sync thread limit from default provider endpoints when present
                for p in merged:
                    if str(p.get("id") or "").strip() != "default":
                        continue
                    eps = p.get("endpoints")
                    if isinstance(eps, list) and eps:
                        apply_endpoints_to_settings_row(row, eps, wire_api=str(p.get("wire_api") or "chat"))
                    break
            if body.default_base_url is not None and body.llm_endpoints is None:
                row.default_base_url = assert_safe_llm_base_url(body.default_base_url)
                # Keep single-endpoint pool URL in sync when only legacy field is updated
                eps = load_pool_endpoints_raw(row)
                if len(eps) == 1 and body.default_base_url is not None:
                    eps[0]["base_url"] = assert_safe_llm_base_url(body.default_base_url)
                    apply_endpoints_to_settings_row(row, eps)
        except ValueError as exc:
            db.rollback()
            raise HTTPException(400, str(exc)) from exc
        if body.llm_roles is not None:
            row.llm_roles = json.dumps(
                {k: v.model_dump() for k, v in body.llm_roles.items()},
                ensure_ascii=False,
            )
        if body.llm_thread_limit is not None and body.llm_endpoints is None:
            limit = max(1, int(body.llm_thread_limit))
            row.llm_thread_limit = limit
            scale_single_endpoint_inflight(row, limit)
        if body.github_pat is not None:
            row.github_pat = body.github_pat
        if body.fofa_key is not None:
            row.fofa_key = body.fofa_key
        if body.fofa_base_url is not None:
            row.fofa_base_url = (body.fofa_base_url or "").strip() or None
        if body.default_model is not None:
            row.default_model = body.default_model
        if body.default_api_key is not None:
            row.default_api_key = body.default_api_key
            if body.llm_endpoints is None:
                eps = load_pool_endpoints_raw(row)
                if len(eps) == 1 and body.default_api_key.strip():
                    eps[0]["api_key"] = body.default_api_key.strip()
                    apply_endpoints_to_settings_row(row, eps)
        if body.context_window is not None:
            row.context_window = int(body.context_window)
        if body.http_proxy is not None:
            row.http_proxy = (body.http_proxy or "").strip()
        if body.chat_proxy is not None:
            row.chat_proxy = (body.chat_proxy or "").strip()
        if body.cli_tools_dir is not None:
            row.cli_tools_dir = (body.cli_tools_dir or "").strip() or None
        if body.jadx_path is not None:
            row.jadx_path = (body.jadx_path or "").strip() or None
        if body.codegraph_path is not None:
            row.codegraph_path = (body.codegraph_path or "").strip() or None
        db.commit()
        db.refresh(row)
        out = settings_out_from_row(row)
    from ..services.llm_thread import llm_thread_limiter

    llm_thread_limiter.refresh_pool(out.llm_endpoints)
    return out


@router.post("/access-token", response_model=SettingsOut)
def update_access_token(body: AccessTokenUpdate) -> SettingsOut:
    with SessionLocal() as db:
        row = db.query(AppSettings).first()
        if row is None:
            row = AppSettings()
            db.add(row)
            db.flush()
        try:
            update_access_token_hash(row, body.current_token, body.new_token)
        except ValueError as exc:
            db.rollback()
            msg = str(exc)
            status = 403 if "当前令牌" in msg else 400
            raise HTTPException(status, msg) from exc
        db.commit()
        db.refresh(row)
        return settings_out_from_row(row)


@router.get("/llm-threads", response_model=LlmThreadUsageOut)
def get_llm_threads() -> LlmThreadUsageOut:
    from ..services.llm_thread import llm_thread_limiter

    snap = llm_thread_limiter.detailed_snapshot()
    return LlmThreadUsageOut(
        used=snap["used"],
        limit=snap["limit"],
        waiting=snap["waiting"],
        endpoints=[LlmEndpointUsageOut(**ep) for ep in snap["endpoints"]],
    )


@router.get("/builtin-audit-modes", response_model=list[BuiltinAuditModeOut])
def list_builtin_audit_modes() -> list[BuiltinAuditModeOut]:
    return [BuiltinAuditModeOut(**row) for row in cam.builtin_prompts()]


@router.get("/custom-audit-modes", response_model=list[CustomAuditModeOut])
def list_custom_audit_modes() -> list[CustomAuditModeOut]:
    with SessionLocal() as db:
        return [CustomAuditModeOut(**cam.custom_mode_out_fields(r)) for r in cam.list_presets(db)]


@router.post("/custom-audit-modes", response_model=CustomAuditModeOut)
def create_custom_audit_mode(body: CustomAuditModeCreate) -> CustomAuditModeOut:
    with SessionLocal() as db:
        try:
            row = cam.create_preset(db, name=body.name, body=body.body)
            db.commit()
            db.refresh(row)
            return CustomAuditModeOut(**cam.custom_mode_out_fields(row))
        except ValueError as exc:
            db.rollback()
            raise HTTPException(400, str(exc)) from exc


@router.patch("/custom-audit-modes/{mode_id}", response_model=CustomAuditModeOut)
def update_custom_audit_mode(mode_id: int, body: CustomAuditModeUpdate) -> CustomAuditModeOut:
    if body.name is None and body.body is None:
        raise HTTPException(400, "没有需要更新的字段")
    with SessionLocal() as db:
        row = db.get(CustomAuditMode, mode_id)
        if not row:
            raise HTTPException(404, "自定义审计模式不存在")
        try:
            cam.update_preset(db, row, name=body.name, body=body.body)
            db.commit()
            db.refresh(row)
            return CustomAuditModeOut(**cam.custom_mode_out_fields(row))
        except ValueError as exc:
            db.rollback()
            raise HTTPException(400, str(exc)) from exc


@router.delete("/custom-audit-modes/{mode_id}")
def delete_custom_audit_mode(mode_id: int) -> dict:
    with SessionLocal() as db:
        row = db.get(CustomAuditMode, mode_id)
        if not row:
            raise HTTPException(404, "自定义审计模式不存在")
        try:
            cam.delete_preset(db, row)
            db.commit()
        except ValueError as exc:
            db.rollback()
            raise HTTPException(400, str(exc)) from exc
    return {"ok": True}


@router.post("/llm/models", response_model=LlmModelListOut)
def probe_llm_models(body: LlmProbeIn) -> LlmModelListOut:
    return list_models(body)


@router.post("/llm/test", response_model=LlmTestOut)
def probe_llm_test(body: LlmProbeIn) -> LlmTestOut:
    return test_connectivity(body)


@router.post("/fofa/test", response_model=FofaTestOut)
def probe_fofa_test(body: FofaProbeIn) -> FofaTestOut:
    return test_fofa_connectivity(body)


@router.post("/github/test", response_model=GithubTestOut)
def probe_github_test(body: GithubProbeIn) -> GithubTestOut:
    return test_github_connectivity(body)


@router.post("/jadx/test", response_model=JadxTestOut)
def probe_jadx_test(body: JadxProbeIn) -> JadxTestOut:
    from ..services.decompile_java import probe_jadx

    result = probe_jadx(body.jadx_path)
    return JadxTestOut(**result)


@router.post("/codegraph/test", response_model=CodegraphTestOut)
def probe_codegraph_test(body: CodegraphProbeIn) -> CodegraphTestOut:
    from ..code_intelligence.cli import probe_codegraph

    result = probe_codegraph(body.codegraph_path)
    return CodegraphTestOut(**result)


@router.post("/logs/purge", response_model=LiveLogPurgeOut)
def purge_live_logs(body: LiveLogPurgeIn) -> LiveLogPurgeOut:
    from ..services.live_log import live_log

    stats = live_log.purge_older_than(body.older_than_days)
    return LiveLogPurgeOut(ok=True, **stats)
