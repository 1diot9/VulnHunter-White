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
    VerifierConsentIn,
    VerifierConsentItem,
    VerifierConsentOut,
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
from ..services.cve_record import format_cve_record_json
from ..services import vuln_followup
from ..services.verifier import (
    awaiting_user_verifier_count,
    list_awaiting_user_vulns,
    parse_verifier_targets,
    resolve_verifier_consent,
)
from ..vuln_types import ALLOWED_SUBMISSION_TIERS, LEGACY_LOW_IMPACT_TIERS, normalize_submission_tier

router = APIRouter(prefix="/api/vulns", tags=["vulns"])
_SCORE_RE = re.compile(r"-\s*校准得分[:：]\s*(-?\d+)")
_UNSAFE_FILENAME_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]+')
ALLOWED_TRACKING_STATUSES = frozenset({"none", "submitted", "ignored"})
ALLOWED_REPORT_KINDS = frozenset({"report", "advisory", "cve"})
REPORT_KIND_FILES = {"report": "report.md", "advisory": "advisory.md", "cve": "cve.json"}


def _tracking_status_out(value: str | None) -> str:
    raw = (value or "none").strip().lower()
    return raw if raw in ALLOWED_TRACKING_STATUSES else "none"


class DownloadBody(BaseModel):
    ids: list[int]


def _report_file(v: Vuln, kind: str = "report") -> Path:
    name = REPORT_KIND_FILES.get(kind, "report.md")
    if kind == "report" and v.report_path:
        return project_root(v.project_id) / v.report_path
    return vuln_dir(v.project_id, v.id) / name


def _read_report_md(v: Vuln) -> str | None:
    path = _report_file(v, "report")
    if not path.is_file():
        return None
    return stamp_produced_at(path.read_text(encoding="utf-8", errors="ignore"), v.created_at)


def _read_advisory_md(v: Vuln) -> str | None:
    path = _report_file(v, "advisory")
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n").strip()
    return (text + "\n") if text else None


def _read_cve_json(v: Vuln) -> str | None:
    return format_cve_record_json(v.project_id, v.id)


def _report_download_filename(vuln_id: int, title: str | None, kind: str = "report") -> str:
    slug = _UNSAFE_FILENAME_RE.sub("_", (title or "").strip())
    slug = re.sub(r"\s+", " ", slug).strip(" ._")
    if len(slug) > 80:
        slug = slug[:80].rstrip(" ._")
    suffix = "-advisory" if kind == "advisory" else "-cve" if kind == "cve" else ""
    if slug:
        return f"vuln-{vuln_id}-{slug}{suffix}.md" if kind != "cve" else f"vuln-{vuln_id}-{slug}{suffix}.json"
    return f"vuln-{vuln_id}{suffix}.md" if kind != "cve" else f"vuln-{vuln_id}{suffix}.json"


def _report_score(v: Vuln) -> int | None:
    if v.severity_score is not None:
        return int(v.severity_score)
    path = _report_file(v, "report")
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


@router.get("/verifier-consent", response_model=list[VerifierConsentItem])
def list_verifier_consent(project_id: int | None = None) -> list[VerifierConsentItem]:
    rows = list_awaiting_user_vulns(project_id)
    out: list[VerifierConsentItem] = []
    with SessionLocal() as db:
        for v in rows:
            # Re-attach project name; list_awaiting_user_vulns expunges rows.
            name = ""
            fresh = db.get(Vuln, v.id)
            if fresh and fresh.project is not None:
                name = fresh.project.name or ""
            elif fresh:
                from ..models import Project

                proj = db.get(Project, fresh.project_id)
                name = proj.name if proj else ""
            out.append(
                VerifierConsentItem(
                    id=v.id,
                    project_id=v.project_id,
                    project_name=name,
                    title=v.title or "",
                    vuln_type=v.vuln_type,
                    severity=v.severity,
                    severity_score=_report_score(fresh) if fresh else None,
                    verifier_ask_reason=getattr(v, "verifier_ask_reason", None),
                    verifier_status=v.verifier_status or "awaiting_user",
                    updated_at=v.updated_at,
                )
            )
    return out


@router.get("/verifier-consent/count")
def verifier_consent_count(project_id: int | None = None) -> dict:
    return {"count": awaiting_user_verifier_count(project_id)}


@router.post("/{vuln_id}/verifier-consent", response_model=VerifierConsentOut)
def post_verifier_consent(vuln_id: int, body: VerifierConsentIn) -> VerifierConsentOut:
    result = resolve_verifier_consent(
        vuln_id,
        action=body.action,
        instruction=body.instruction or "",
    )
    if not result.get("ok"):
        raise HTTPException(400, str(result.get("error") or "无法处理确认"))
    return VerifierConsentOut(**{k: result.get(k) for k in (
        "ok",
        "action",
        "vuln_id",
        "verifier_status",
        "instruction",
        "message",
        "error",
    )})


@router.get("/{vuln_id}", response_model=VulnDetail)
def get_vuln(vuln_id: int) -> VulnDetail:
    with SessionLocal() as db:
        v = db.query(Vuln).options(joinedload(Vuln.project)).filter(Vuln.id == vuln_id).first()
        if not v:
            raise HTTPException(404, "漏洞不存在")
        report_md = _read_report_md(v)
        advisory_md = _read_advisory_md(v)
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
            advisory_md=advisory_md,
            cve_json=_read_cve_json(v),
            merged_from_ids=merged_from,
            verifier_poc=getattr(v, "verifier_poc", None),
            verifier_response=getattr(v, "verifier_response", None),
            verifier_targets=parse_verifier_targets(getattr(v, "verifier_targets", None)),
            verifier_fofa_query=getattr(v, "verifier_fofa_query", None),
            can_dynamic_verify=can_dynamic,
            dynamic_verify_queued=queued_dynamic,
        )


@router.get("/{vuln_id}/download")
def download_vuln_report(vuln_id: int, kind: str = "report") -> Response:
    if kind not in ALLOWED_REPORT_KINDS:
        raise HTTPException(400, "kind 须为 report|advisory|cve")
    with SessionLocal() as db:
        v = db.get(Vuln, vuln_id)
        if not v:
            raise HTTPException(404, "漏洞不存在")
        if kind == "advisory":
            text = _read_advisory_md(v)
            media_type = "text/markdown; charset=utf-8"
            ascii_name = f"vuln-{v.id}-advisory.md"
        elif kind == "cve":
            text = _read_cve_json(v)
            media_type = "application/json; charset=utf-8"
            ascii_name = f"vuln-{v.id}-cve.json"
        else:
            text = _read_report_md(v)
            media_type = "text/markdown; charset=utf-8"
            ascii_name = f"vuln-{v.id}.md"
        if text is None:
            raise HTTPException(404, "报告不存在")
        filename = _report_download_filename(v.id, v.title, kind)
        return Response(
            content=text.encode("utf-8"),
            media_type=media_type,
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
                report = _read_report_md(v)
                if report is not None:
                    zf.writestr(f"vuln-{v.id}/report.md", report)
                advisory = _read_advisory_md(v)
                if advisory is not None:
                    zf.writestr(f"vuln-{v.id}/advisory.md", advisory)
                cve_json = _read_cve_json(v)
                if cve_json is not None:
                    zf.writestr(f"vuln-{v.id}/cve.json", cve_json)
                for fp in vdir.glob("*"):
                    if not fp.is_file() or fp.name in REPORT_KIND_FILES.values():
                        continue
                    zf.write(fp, arcname=f"vuln-{v.id}/{fp.name}")
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=vulns.zip"},
    )
