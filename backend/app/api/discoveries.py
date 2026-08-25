"""GitHub repo discovery from public GHSA advisories."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from ..schemas import (
    GithubCandidateListOut,
    GithubCandidateOut,
    GithubDiscoverSearchIn,
    GithubDiscoverSearchOut,
)
from ..services import github_discover as discover

router = APIRouter(prefix="/api/discoveries", tags=["discoveries"])


@router.get("", response_model=GithubCandidateListOut)
def list_discoveries(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> GithubCandidateListOut:
    data = discover.list_candidates(limit=limit, offset=offset)
    return GithubCandidateListOut(
        items=[GithubCandidateOut.model_validate(item) for item in data["items"]],
        total=int(data["total"]),
        limit=int(data["limit"]),
        offset=int(data["offset"]),
    )


@router.post("/search", response_model=GithubDiscoverSearchOut)
def search_discoveries(body: GithubDiscoverSearchIn | None = None) -> GithubDiscoverSearchOut:
    limit = discover.clamp_search_limit(body.limit if body else discover.DEFAULT_SEARCH_LIMIT)
    result = discover.search_candidates(limit=limit)
    if not result.get("ok"):
        # Still return structured body for UI; raise only on hard auth failure
        err = str(result.get("error") or "搜索失败")
        if "401" in err or "PAT" in err:
            raise HTTPException(401, err)
        raise HTTPException(502, err)
    return GithubDiscoverSearchOut(
        ok=True,
        error=None,
        added=int(result.get("added") or 0),
        items=[GithubCandidateOut.model_validate(item) for item in (result.get("items") or [])],
        scanned_advisories=int(result.get("scanned_advisories") or 0),
        scanned_repos=int(result.get("scanned_repos") or 0),
        skipped_seen=int(result.get("skipped_seen") or 0),
        pages=int(result.get("pages") or 0),
        authenticated=bool(result.get("authenticated")),
        warning=result.get("warning"),
        limit=int(result.get("limit") or limit),
    )


@router.delete("/{candidate_id}", response_model=GithubCandidateOut)
def dismiss_discovery(candidate_id: int) -> GithubCandidateOut:
    row = discover.dismiss_candidate(candidate_id)
    if row is None:
        raise HTTPException(404, "候选不存在")
    return GithubCandidateOut.model_validate(row)
