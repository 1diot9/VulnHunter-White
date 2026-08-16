from __future__ import annotations

import io
import zipfile

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import joinedload

from ..models import SessionLocal, Vuln
from ..schemas import VulnDetail, VulnOut
from ..services.paths import project_root, vuln_dir
from ..services.report import stamp_produced_at

router = APIRouter(prefix="/api/vulns", tags=["vulns"])


class DownloadBody(BaseModel):
    ids: list[int]


def _vuln_out(v: Vuln) -> VulnOut:
    name = v.project.name if v.project is not None else ""
    return VulnOut.model_validate(v).model_copy(update={"project_name": name})


@router.get("", response_model=list[VulnOut])
def list_vulns(project_id: int | None = None, status: str | None = None) -> list[VulnOut]:
    with SessionLocal() as db:
        q = db.query(Vuln).options(joinedload(Vuln.project))
        if project_id is not None:
            q = q.filter(Vuln.project_id == project_id)
        if status:
            if status == "confirmed":
                q = q.filter(Vuln.status.in_(("confirmed", "static_only")))
            else:
                q = q.filter(Vuln.status == status)
        rows = q.order_by(Vuln.id.desc()).all()
        return [_vuln_out(r) for r in rows]


@router.get("/{vuln_id}", response_model=VulnDetail)
def get_vuln(vuln_id: int) -> VulnDetail:
    with SessionLocal() as db:
        v = db.query(Vuln).options(joinedload(Vuln.project)).filter(Vuln.id == vuln_id).first()
        if not v:
            raise HTTPException(404, "漏洞不存在")
        report_md = None
        if v.report_path:
            p = project_root(v.project_id) / v.report_path
            if p.exists():
                report_md = stamp_produced_at(
                    p.read_text(encoding="utf-8", errors="ignore"),
                    v.created_at,
                )
        return VulnDetail(
            **_vuln_out(v).model_dump(),
            source_sink=v.source_sink,
            auth_premise=v.auth_premise,
            http_request=v.http_request,
            poc_code=v.poc_code,
            expected_evidence=v.expected_evidence,
            report_md=report_md,
        )


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
