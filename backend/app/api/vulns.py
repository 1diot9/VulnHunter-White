from __future__ import annotations

import io
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import cast, func, or_
from sqlalchemy.orm import joinedload, load_only
from sqlalchemy.types import String

from ..target_kind import normalize_target_kind
from ..models import Project, SessionLocal, Vuln
from ..schemas import (
    HarnessConsentItem,
    HarnessConsentOut,
    VerifierConsentIn,
    VerifierConsentItem,
    VerifierConsentOut,
    VulnCalendarDay,
    VulnCalendarOut,
    VulnDetail,
    VulnFollowUpIn,
    VulnFollowUpThread,
    VulnListOut,
    VulnOut,
    VulnReportApplyIn,
    VulnReportApplyOut,
    VulnReportRevisionIn,
    VulnReportRevisionOut,
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
from ..services.harness_ask import (
    HARNESS_ASK_AWAITING,
    awaiting_harness_count,
    resolve_harness_consent,
)
from ..services.verifier import (
    VERIFIER_AWAITING_USER,
    awaiting_user_verifier_count,
    parse_verifier_targets,
    resolve_verifier_consent,
)
from ..vuln_types import (
    ALLOWED_SUBMISSION_TIERS,
    ALLOWED_VULN_TYPES,
    LEGACY_LOW_IMPACT_TIERS,
    VULN_TYPES,
    normalize_submission_tier,
)

router = APIRouter(prefix="/api/vulns", tags=["vulns"])
_CVSS_SCORE_RE = re.compile(r"-\s*CVSS\s*3\.[01][:：]\s*(\d+(?:\.\d+)?)")
_SCORE_RE = re.compile(r"-\s*校准得分[:：]\s*(-?\d+(?:\.\d+)?)")
_UNSAFE_FILENAME_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]+')
_CREATED_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
ALLOWED_TRACKING_STATUSES = frozenset({"none", "submitted", "ignored"})
ALLOWED_REPORT_KINDS = frozenset({"report", "advisory", "cve"})
REPORT_KIND_FILES = {"report": "report.md", "advisory": "advisory.md", "cve": "cve.json"}
_CONFIRMED_STATUSES = frozenset({"confirmed", "static_only"})
_CALENDAR_STATUSES = frozenset({"confirmed", "static_only", "false_positive"})
_CST = timezone(timedelta(hours=8))


def _tracking_status_out(value: str | None) -> str:
    raw = (value or "none").strip().lower()
    return raw if raw in ALLOWED_TRACKING_STATUSES else "none"


def _ensure_aware_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_shanghai_date(dt: datetime) -> str:
    return _ensure_aware_utc(dt).astimezone(_CST).strftime("%Y-%m-%d")


def _parse_created_date(value: str) -> tuple[int, int, int]:
    match = _CREATED_DATE_RE.fullmatch((value or "").strip())
    if not match:
        raise HTTPException(400, "created_date 须为 YYYY-MM-DD")
    year, month, day = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    try:
        datetime(year, month, day, tzinfo=_CST)
    except ValueError as exc:
        raise HTTPException(400, "created_date 不是合法日期") from exc
    return year, month, day


def _shanghai_day_bounds(year: int, month: int, day: int) -> tuple[datetime, datetime]:
    start_cst = datetime(year, month, day, tzinfo=_CST)
    end_cst = start_cst + timedelta(days=1)
    return start_cst.astimezone(timezone.utc), end_cst.astimezone(timezone.utc)


def _shanghai_month_bounds(year: int, month: int) -> tuple[datetime, datetime]:
    if month < 1 or month > 12:
        raise HTTPException(400, "month 须为 1–12")
    start_cst = datetime(year, month, 1, tzinfo=_CST)
    if month == 12:
        end_cst = datetime(year + 1, 1, 1, tzinfo=_CST)
    else:
        end_cst = datetime(year, month + 1, 1, tzinfo=_CST)
    return start_cst.astimezone(timezone.utc), end_cst.astimezone(timezone.utc)


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
    if kind in {"zip", "bundle"}:
        ext = ".zip"
    elif kind == "cve":
        ext = ".json"
    else:
        ext = ".md"
    if slug:
        return f"vuln-{vuln_id}-{slug}{suffix}{ext}"
    return f"vuln-{vuln_id}{suffix}{ext}"


def _write_vuln_bundle(zf: zipfile.ZipFile, v: Vuln) -> None:
    """Pack the same files as bulk download: reports, CVE JSON, PoC, and sibling artifacts."""
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


def _vuln_bundle_bytes(vulns: list[Vuln]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for v in vulns:
            _write_vuln_bundle(zf, v)
    return buf.getvalue()


def _zip_attachment(data: bytes, *, ascii_name: str, filename: str) -> Response:
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{ascii_name}"; '
                f"filename*=UTF-8''{quote(filename)}"
            ),
        },
    )


_VULN_LIST_COLUMNS = (
    Vuln.id,
    Vuln.project_id,
    Vuln.title,
    Vuln.vuln_type,
    Vuln.severity,
    Vuln.severity_score,
    Vuln.cvss_vector,
    Vuln.cvss_score,
    Vuln.cwe,
    Vuln.file_path,
    Vuln.line_no,
    Vuln.status,
    Vuln.tracking_status,
    Vuln.evidence_level,
    Vuln.attack_surface,
    Vuln.required_account,
    Vuln.submission_tier,
    Vuln.submission_reason,
    Vuln.mining_path,
    Vuln.root_cause_key,
    Vuln.merged_into_id,
    Vuln.review_rounds,
    Vuln.return_reason,
    Vuln.fp_kind,
    Vuln.intended_behavior,
    Vuln.config_premise,
    Vuln.report_path,
    Vuln.verifier_status,
    Vuln.verifier_verified_url,
    Vuln.verifier_ask_reason,
    Vuln.verifier_user_instruction,
    Vuln.verifier_consent,
    Vuln.created_at,
    Vuln.updated_at,
)


def _report_score(v: Vuln, *, read_report: bool = True) -> float | None:
    if v.cvss_score is not None:
        return float(v.cvss_score)
    if v.severity_score is not None:
        return float(v.severity_score)
    if not read_report:
        return None
    path = _report_file(v, "report")
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = _CVSS_SCORE_RE.search(text)
    if match:
        return float(match.group(1))
    match = _SCORE_RE.search(text)
    return float(match.group(1)) if match else None


def _vuln_out(v: Vuln, *, read_report: bool = True) -> VulnOut:
    name = v.project.name if v.project is not None else ""
    kind = normalize_target_kind(getattr(v.project, "target_kind", None) if v.project is not None else None)
    return VulnOut.model_validate(v).model_copy(
        update={
            "project_name": name,
            "project_target_kind": kind,
            "severity_score": _report_score(v, read_report=read_report),
            "tracking_status": _tracking_status_out(v.tracking_status),
        }
    )


def _apply_vuln_search(query, q: str):
    tokens = [t for t in (q or "").strip().lower().split() if t]
    if not tokens:
        return query
    for token in tokens:
        pattern = f"%{token}%"
        query = query.filter(
            or_(
                Vuln.title.ilike(pattern),
                Vuln.vuln_type.ilike(pattern),
                Vuln.cwe.ilike(pattern),
                Vuln.file_path.ilike(pattern),
                Vuln.root_cause_key.ilike(pattern),
                Vuln.status.ilike(pattern),
                Vuln.severity.ilike(pattern),
                Vuln.submission_tier.ilike(pattern),
                Vuln.tracking_status.ilike(pattern),
                Vuln.attack_surface.ilike(pattern),
                Vuln.evidence_level.ilike(pattern),
                Vuln.mining_path.ilike(pattern),
                Vuln.verifier_status.ilike(pattern),
                Vuln.verifier_verified_url.ilike(pattern),
                Vuln.config_premise.ilike(pattern),
                Vuln.project.has(Project.name.ilike(pattern)),
                cast(Vuln.id, String).ilike(pattern),
                cast(Vuln.project_id, String).ilike(pattern),
            )
        )
    return query


def _apply_vuln_filters(
    q,
    *,
    project_id: int | None = None,
    status: str | None = None,
    attack_surface: str | None = None,
    submission_tier: str | None = None,
    root_cause_key: str | None = None,
    tracking_status: str | None = None,
    created_date: str | None = None,
    vuln_type: str | None = None,
    search: str = "",
):
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
    if vuln_type:
        if vuln_type not in ALLOWED_VULN_TYPES:
            raise HTTPException(400, "vuln_type 须为 " + "|".join(VULN_TYPES))
        q = q.filter(Vuln.vuln_type == vuln_type)
    if root_cause_key:
        q = q.filter(Vuln.root_cause_key == root_cause_key)
    if created_date:
        y, m, d = _parse_created_date(created_date)
        start_utc, end_utc = _shanghai_day_bounds(y, m, d)
        q = q.filter(Vuln.created_at >= start_utc, Vuln.created_at < end_utc)
    return _apply_vuln_search(q, search)


@router.get("", response_model=VulnListOut)
def list_vulns(
    project_id: int | None = None,
    status: str | None = None,
    attack_surface: str | None = None,
    submission_tier: str | None = None,
    root_cause_key: str | None = None,
    tracking_status: str | None = None,
    created_date: str | None = None,
    vuln_type: str | None = None,
    q: str = Query(""),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> VulnListOut:
    filters = dict(
        project_id=project_id,
        status=status,
        attack_surface=attack_surface,
        submission_tier=submission_tier,
        root_cause_key=root_cause_key,
        tracking_status=tracking_status,
        created_date=created_date,
        vuln_type=vuln_type,
        search=q,
    )
    with SessionLocal() as db:
        total = int(_apply_vuln_filters(db.query(func.count(Vuln.id)), **filters).scalar() or 0)
        rows_q = db.query(Vuln).options(
            load_only(*_VULN_LIST_COLUMNS),
            joinedload(Vuln.project).load_only(Project.id, Project.name, Project.target_kind),
        )
        rows = (
            _apply_vuln_filters(rows_q, **filters)
            .order_by(Vuln.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return VulnListOut(
            items=[_vuln_out(r, read_report=False) for r in rows],
            total=total,
            limit=limit,
            offset=offset,
        )


@router.get("/calendar", response_model=VulnCalendarOut)
def vuln_calendar(
    year: int,
    month: int,
    project_id: int | None = None,
) -> VulnCalendarOut:
    if year < 1970 or year > 2100:
        raise HTTPException(400, "year 超出范围")
    start_utc, end_utc = _shanghai_month_bounds(year, month)
    tallies: dict[str, dict[str, int]] = defaultdict(lambda: {"confirmed": 0, "false_positive": 0})
    with SessionLocal() as db:
        q = db.query(Vuln.status, Vuln.created_at).filter(
            Vuln.status.in_(tuple(_CALENDAR_STATUSES)),
            Vuln.created_at >= start_utc,
            Vuln.created_at < end_utc,
        )
        if project_id is not None:
            q = q.filter(Vuln.project_id == project_id)
        for status, created_at in q.all():
            day = _to_shanghai_date(created_at)
            if status in _CONFIRMED_STATUSES:
                tallies[day]["confirmed"] += 1
            elif status == "false_positive":
                tallies[day]["false_positive"] += 1
    days = [
        VulnCalendarDay(date=day, confirmed=counts["confirmed"], false_positive=counts["false_positive"])
        for day, counts in sorted(tallies.items())
    ]
    return VulnCalendarOut(year=year, month=month, days=days)


@router.get("/verifier-consent", response_model=list[VerifierConsentItem])
def list_verifier_consent(project_id: int | None = None) -> list[VerifierConsentItem]:
    with SessionLocal() as db:
        q = (
            db.query(Vuln, Project.name)
            .outerjoin(Project, Project.id == Vuln.project_id)
            .filter(Vuln.verifier_status == VERIFIER_AWAITING_USER)
        )
        if project_id is not None:
            q = q.filter(Vuln.project_id == int(project_id))
        rows = q.order_by(Vuln.id.asc()).all()
        return [
            VerifierConsentItem(
                id=v.id,
                project_id=v.project_id,
                project_name=name or "",
                title=v.title or "",
                vuln_type=v.vuln_type,
                severity=v.severity,
                severity_score=_report_score(v, read_report=False),
                cvss_vector=getattr(v, "cvss_vector", None),
                verifier_ask_reason=getattr(v, "verifier_ask_reason", None),
                verifier_status=v.verifier_status or "awaiting_user",
                updated_at=v.updated_at,
            )
            for v, name in rows
        ]


@router.get("/verifier-consent/count")
def verifier_consent_count(project_id: int | None = None) -> dict:
    verifier = awaiting_user_verifier_count(project_id)
    harness = awaiting_harness_count(project_id)
    return {"count": verifier + harness, "verifier": verifier, "harness": harness}


@router.get("/harness-consent", response_model=list[HarnessConsentItem])
def list_harness_consent(project_id: int | None = None) -> list[HarnessConsentItem]:
    with SessionLocal() as db:
        q = (
            db.query(Vuln, Project.name)
            .outerjoin(Project, Project.id == Vuln.project_id)
            .filter(Vuln.harness_ask_status == HARNESS_ASK_AWAITING)
        )
        if project_id is not None:
            q = q.filter(Vuln.project_id == int(project_id))
        rows = q.order_by(Vuln.id.asc()).all()
        return [
            HarnessConsentItem(
                id=v.id,
                project_id=v.project_id,
                project_name=name or "",
                title=v.title or "",
                vuln_type=v.vuln_type,
                severity=v.severity,
                severity_score=_report_score(v, read_report=False),
                cvss_vector=getattr(v, "cvss_vector", None),
                harness_ask_reason=getattr(v, "harness_ask_reason", None),
                harness_ask_status=v.harness_ask_status or "awaiting_user",
                updated_at=v.updated_at,
            )
            for v, name in rows
        ]


@router.post("/{vuln_id}/harness-consent", response_model=HarnessConsentOut)
def post_harness_consent(vuln_id: int, body: VerifierConsentIn) -> HarnessConsentOut:
    result = resolve_harness_consent(
        vuln_id,
        action=body.action,
        instruction=body.instruction or "",
    )
    if not result.get("ok"):
        raise HTTPException(400, str(result.get("error") or "无法处理确认"))
    return HarnessConsentOut(
        **{
            k: result.get(k)
            for k in ("ok", "action", "vuln_id", "instruction", "message", "error")
        }
    )


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
def download_vuln_report(vuln_id: int, kind: str | None = None) -> Response:
    bundle = kind in (None, "", "zip", "bundle")
    if not bundle and kind not in ALLOWED_REPORT_KINDS:
        raise HTTPException(400, "kind 须为 report|advisory|cve")
    with SessionLocal() as db:
        v = db.get(Vuln, vuln_id)
        if not v:
            raise HTTPException(404, "漏洞不存在")
        if bundle:
            return _zip_attachment(
                _vuln_bundle_bytes([v]),
                ascii_name=f"vuln-{v.id}.zip",
                filename=_report_download_filename(v.id, v.title, "zip"),
            )
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
        filename = _report_download_filename(v.id, v.title, kind or "report")
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


@router.post("/{vuln_id}/report-revisions", response_model=VulnReportRevisionOut)
def generate_vuln_report_revision(vuln_id: int, body: VulnReportRevisionIn) -> VulnReportRevisionOut:
    try:
        return VulnReportRevisionOut.model_validate(
            vuln_followup.generate_report_revision(vuln_id, body.kind, body.instruction)
        )
    except vuln_followup.FollowUpNotFound as e:
        raise HTTPException(404, str(e)) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except vuln_followup.FollowUpLlmError as e:
        raise HTTPException(502, str(e)) from e


@router.post("/{vuln_id}/report-revisions/apply", response_model=VulnReportApplyOut)
def apply_vuln_report_revision(vuln_id: int, body: VulnReportApplyIn) -> VulnReportApplyOut:
    try:
        return VulnReportApplyOut.model_validate(
            vuln_followup.apply_report_revision(vuln_id, body.kind, body.content, body.note or "")
        )
    except vuln_followup.FollowUpNotFound as e:
        raise HTTPException(404, str(e)) from e
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


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
def download_vulns(body: DownloadBody) -> Response:
    with SessionLocal() as db:
        vulns: list[Vuln] = []
        for vid in body.ids:
            v = db.get(Vuln, vid)
            if v:
                vulns.append(v)
        data = _vuln_bundle_bytes(vulns)
        if len(vulns) == 1:
            v = vulns[0]
            return _zip_attachment(
                data,
                ascii_name=f"vuln-{v.id}.zip",
                filename=_report_download_filename(v.id, v.title, "zip"),
            )
    return _zip_attachment(data, ascii_name="vulns.zip", filename="vulns.zip")
