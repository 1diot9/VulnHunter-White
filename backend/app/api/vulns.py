from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from ..models import SessionLocal, Vuln
from ..schemas import (
    VulnDetail,
    VulnFollowUpIn,
    VulnFollowUpThread,
    VulnOut,
    VulnTrackingBatchIn,
    VulnTrackingIn,
)
from ..services.paths import project_root, vuln_dir
from ..services.pipeline import (
    DynamicVerifyRequestError,
    dynamic_verify_flags,
    request_dynamic_verify,
)
from ..services.poc_script import read_poc_code
from ..services.report import stamp_produced_at
from ..services import vuln_followup
from ..services.verifier import parse_verifier_targets
from ..vuln_types import ALLOWED_SUBMISSION_TIERS, LEGACY_LOW_IMPACT_TIERS, normalize_submission_tier

router = APIRouter(prefix="/api/vulns", tags=["vulns"])
_SCORE_RE = re.compile(r"-\s*校准得分[:：]\s*(-?\d+)")
_UNSAFE_FILENAME_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]+')
ALLOWED_TRACKING_STATUSES = frozenset({"none", "submitted", "ignored"})


def _tracking_status_out(value: str | None) -> str:
    raw = (value or "none").strip().lower()
    return raw if raw in ALLOWED_TRACKING_STATUSES else "none"


class DownloadBody(BaseModel):
    ids: list[int]


def _report_file(v: Vuln) -> Path:
    if v.report_path:
        return project_root(v.project_id) / v.report_path
    return vuln_dir(v.project_id, v.id) / "report.md"


def _read_report_md(v: Vuln) -> str | None:
    path = _report_file(v)
    if not path.is_file():
        return None
    return stamp_produced_at(path.read_text(encoding="utf-8", errors="ignore"), v.created_at)


def _report_download_filename(vuln_id: int, title: str | None) -> str:
    slug = _UNSAFE_FILENAME_RE.sub("_", (title or "").strip())
    slug = re.sub(r"\s+", " ", slug).strip(" ._")
    if len(slug) > 80:
        slug = slug[:80].rstrip(" ._")
    if slug:
        return f"vuln-{vuln_id}-{slug}.md"
    return f"vuln-{vuln_id}.md"


def _report_score(v: Vuln) -> int | None:
    if v.severity_score is not None:
        return int(v.severity_score)
    path = _report_file(v)
    if not path.is_file():
        return None
    match = _SCORE_RE.search(path.read_text(encoding="utf-8", errors="ignore"))
    return int(match.group(1)) if match else None


def _vuln_out(v: Vuln) -> VulnOut:
    name = v.project.name if v.project is not None else ""
    return VulnOut.model_validate(v).model_copy(
        update={
            "project_name": name,
            "severity_score": _report_score(v),
            "tracking_status": _tracking_status_out(v.tracking_status),
        }
    )


@router.get("", response_model=list[VulnOut])
def list_vulns(
    project_id: int | None = None,
    status: str | None = None,
    attack_surface: str | None = None,
    submission_tier: str | None = None,
    root_cause_key: str | None = None,
    tracking_status: str | None = None,
) -> list[VulnOut]:
    with SessionLocal() as db:
        q = db.query(Vuln).options(joinedload(Vuln.project))
        if project_id is not None:
            q = q.filter(Vuln.project_id == project_id)
        if status:
            if status == "confirmed":
                q = q.filter(Vuln.status.in_(("confirmed", "static_only")))
            else:
                q = q.filter(Vuln.status == status)
        if tracking_status:
            if tracking_status not in ALLOWED_TRACKING_STATUSES:
                raise HTTPException(400, "tracking_status 须为 none|submitted|ignored")
            if tracking_status == "none":
                q = q.filter(or_(Vuln.tracking_status == "none", Vuln.tracking_status.is_(None)))
            else:
                q = q.filter(Vuln.tracking_status == tracking_status)
        if attack_surface:
            if attack_surface not in ("frontend", "backend"):
                raise HTTPException(400, "attack_surface 须为 frontend|backend")
            q = q.filter(Vuln.attack_surface == attack_surface)
        if submission_tier:
            if submission_tier == "untiered":
                q = q.filter(Vuln.submission_tier.is_(None))
            else:
                try:
                    normalized = normalize_submission_tier(submission_tier)
                except ValueError:
                    raise HTTPException(
                        400,
                        "submission_tier 须为 "
                        + "|".join(sorted(ALLOWED_SUBMISSION_TIERS))
                        + "|untiered",
                    ) from None
                if normalized == "low_impact":
                    q = q.filter(Vuln.submission_tier.in_(tuple(LEGACY_LOW_IMPACT_TIERS)))
                else:
                    q = q.filter(Vuln.submission_tier == normalized)
        if root_cause_key:
            q = q.filter(Vuln.root_cause_key == root_cause_key)
        rows = q.order_by(Vuln.id.desc()).all()
        return [_vuln_out(r) for r in rows]


@router.get("/{vuln_id}", response_model=VulnDetail)
def get_vuln(vuln_id: int) -> VulnDetail:
    with SessionLocal() as db:
        v = db.query(Vuln).options(joinedload(Vuln.project)).filter(Vuln.id == vuln_id).first()
        if not v:
            raise HTTPException(404, "漏洞不存在")
        report_md = _read_report_md(v)
        merged_from = [
            row.id
            for row in (
                db.query(Vuln)
                .filter(Vuln.project_id == v.project_id, Vuln.merged_into_id == v.id)
                .order_by(Vuln.id.asc())
                .all()
            )
        ]
        can_dynamic, queued_dynamic = dynamic_verify_flags(v, project=v.project)
        return VulnDetail(
            **_vuln_out(v).model_dump(),
            source_sink=v.source_sink,
            auth_premise=v.auth_premise,
            http_request=v.http_request,
            poc_code=read_poc_code(v.project_id, v.id, fallback=v.poc_code),
            expected_evidence=v.expected_evidence,
            report_md=report_md,
            merged_from_ids=merged_from,
            verifier_poc=getattr(v, "verifier_poc", None),
            verifier_response=getattr(v, "verifier_response", None),
            verifier_targets=parse_verifier_targets(getattr(v, "verifier_targets", None)),
            verifier_fofa_query=getattr(v, "verifier_fofa_query", None),
            can_dynamic_verify=can_dynamic,
            dynamic_verify_queued=queued_dynamic,
        )


@router.get("/{vuln_id}/download")
def download_vuln_report(vuln_id: int) -> Response:
    with SessionLocal() as db:
        v = db.get(Vuln, vuln_id)
        if not v:
            raise HTTPException(404, "漏洞不存在")
        text = _read_report_md(v)
        if text is None:
            raise HTTPException(404, "报告不存在")
        filename = _report_download_filename(v.id, v.title)
        ascii_name = f"vuln-{v.id}.md"
        return Response(
            content=text.encode("utf-8"),
            media_type="text/markdown; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{ascii_name}"; '
                    f"filename*=UTF-8''{quote(filename)}"
                ),
            },
        )


@router.post("/{vuln_id}/dynamic-verify")
def start_dynamic_verify(vuln_id: int) -> dict:
    try:
        return request_dynamic_verify(vuln_id)
    except DynamicVerifyRequestError as e:
        raise HTTPException(e.status_code, str(e)) from e


@router.get("/{vuln_id}/follow-ups", response_model=VulnFollowUpThread)
def list_vuln_followups(vuln_id: int) -> VulnFollowUpThread:
    try:
        return VulnFollowUpThread.model_validate(vuln_followup.list_followups(vuln_id))
    except vuln_followup.FollowUpNotFound as e:
        raise HTTPException(404, str(e)) from e


@router.post("/{vuln_id}/follow-ups", response_model=VulnFollowUpThread)
def ask_vuln_followup(vuln_id: int, body: VulnFollowUpIn) -> VulnFollowUpThread:
    try:
        return VulnFollowUpThread.model_validate(vuln_followup.ask_followup(vuln_id, body.question))
    except vuln_followup.FollowUpNotFound as e:
        raise HTTPException(404, str(e)) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except vuln_followup.ReviewerContextMissing as e:
        raise HTTPException(409, str(e)) from e
    except vuln_followup.FollowUpLlmError as e:
        raise HTTPException(502, str(e)) from e


@router.patch("/{vuln_id}", response_model=VulnOut)
def update_vuln_tracking(vuln_id: int, body: VulnTrackingIn) -> VulnOut:
    with SessionLocal() as db:
        v = db.query(Vuln).options(joinedload(Vuln.project)).filter(Vuln.id == vuln_id).first()
        if not v:
            raise HTTPException(404, "漏洞不存在")
        v.tracking_status = body.tracking_status
        db.commit()
        db.refresh(v)
        return _vuln_out(v)


@router.post("/mark", response_model=list[VulnOut])
def mark_vulns(body: VulnTrackingBatchIn) -> list[VulnOut]:
    with SessionLocal() as db:
        rows = (
            db.query(Vuln)
            .options(joinedload(Vuln.project))
            .filter(Vuln.id.in_(body.ids))
            .all()
        )
        by_id = {row.id: row for row in rows}
        updated: list[Vuln] = []
        for vid in body.ids:
            v = by_id.get(vid)
            if not v:
                continue
            v.tracking_status = body.tracking_status
            updated.append(v)
        db.commit()
        for v in updated:
            db.refresh(v)
        return [_vuln_out(v) for v in updated]


@router.post("/download")
def download_vulns(body: DownloadBody) -> StreamingResponse:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        with SessionLocal() as db:
            for vid in body.ids:
                v = db.get(Vuln, vid)
                if not v:
                    continue
                vdir = vuln_dir(v.project_id, v.id)
                for fp in vdir.glob("*"):
                    if fp.is_file():
                        zf.write(fp, arcname=f"vuln-{v.id}/{fp.name}")
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=vulns.zip"},
    )
