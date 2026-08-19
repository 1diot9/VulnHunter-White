"""Global custom audit-mode library and project snapshot helpers."""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..audit_mode import (
    AUDIT_MODE_CUSTOM,
    format_custom_overlay,
    normalize_custom_audit_name,
    normalize_custom_audit_prompt,
)
from ..models import CustomAuditMode, Project
from ..prompts import load_prompt


def custom_mode_out_fields(preset: CustomAuditMode) -> dict:
    return {
        "id": preset.id,
        "name": preset.name,
        "body": preset.body,
        "created_at": preset.created_at,
        "updated_at": preset.updated_at,
    }


def list_presets(db: Session) -> list[CustomAuditMode]:
    return db.query(CustomAuditMode).order_by(CustomAuditMode.id.asc()).all()


def get_preset(db: Session, preset_id: int) -> CustomAuditMode | None:
    return db.get(CustomAuditMode, int(preset_id))


def create_preset(db: Session, *, name: str, body: str) -> CustomAuditMode:
    name_n = normalize_custom_audit_name(name)
    body_n = normalize_custom_audit_prompt(body)
    if db.query(CustomAuditMode).filter(CustomAuditMode.name == name_n).first():
        raise ValueError(f"自定义审计模式名称已存在：{name_n}")
    row = CustomAuditMode(name=name_n, body=body_n)
    db.add(row)
    db.flush()
    return row


def update_preset(
    db: Session,
    preset: CustomAuditMode,
    *,
    name: str | None = None,
    body: str | None = None,
) -> CustomAuditMode:
    if name is not None:
        name_n = normalize_custom_audit_name(name)
        clash = (
            db.query(CustomAuditMode)
            .filter(CustomAuditMode.name == name_n, CustomAuditMode.id != preset.id)
            .first()
        )
        if clash:
            raise ValueError(f"自定义审计模式名称已存在：{name_n}")
        preset.name = name_n
    if body is not None:
        preset.body = normalize_custom_audit_prompt(body)
    db.flush()
    return preset


def delete_preset(db: Session, preset: CustomAuditMode) -> None:
    refs = (
        db.query(Project)
        .filter(Project.custom_audit_mode_id == preset.id)
        .count()
    )
    if refs:
        raise ValueError(f"仍有 {refs} 个项目引用该自定义模式，请先在项目中改用其他模式后再删除")
    db.delete(preset)
    db.flush()


def builtin_prompts() -> list[dict[str, str]]:
    return [
        {
            "id": "bounty",
            "label": "赏金模式",
            "body": load_prompt("modes/bounty.md").strip(),
        },
        {
            "id": "full",
            "label": "全量模式",
            "body": load_prompt("modes/full.md").strip(),
        },
    ]


def clear_project_custom_snapshot(project: Project) -> None:
    project.custom_audit_mode_id = None
    project.custom_audit_mode_name = None
    project.custom_audit_prompt = None


def apply_project_custom_snapshot(project: Project, preset: CustomAuditMode) -> None:
    body = normalize_custom_audit_prompt(preset.body)
    project.audit_mode = AUDIT_MODE_CUSTOM
    project.custom_audit_mode_id = preset.id
    project.custom_audit_mode_name = preset.name
    project.custom_audit_prompt = body


def resolve_custom_for_project(
    db: Session,
    *,
    custom_audit_mode_id: int | None,
) -> CustomAuditMode:
    if custom_audit_mode_id is None:
        raise ValueError("自定义模式须指定 custom_audit_mode_id")
    preset = get_preset(db, int(custom_audit_mode_id))
    if not preset:
        raise ValueError("自定义审计模式不存在，请先在设置页创建")
    normalize_custom_audit_prompt(preset.body)
    return preset


def project_custom_overlay(project: Project | None) -> str:
    if not project:
        return ""
    name = (getattr(project, "custom_audit_mode_name", None) or "").strip()
    body = (getattr(project, "custom_audit_prompt", None) or "").strip()
    if not body:
        return ""
    return format_custom_overlay(name=name, body=body)
