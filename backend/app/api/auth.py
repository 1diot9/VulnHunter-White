from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..schemas import AuthLoginIn, AuthLoginOut, AuthStatusOut
from ..services.access_token import configured_token_hash, token_matches

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/status", response_model=AuthStatusOut)
def auth_status() -> AuthStatusOut:
    required = bool(configured_token_hash())
    return AuthStatusOut(ok=True, required=required)


@router.post("/login", response_model=AuthLoginOut)
def auth_login(body: AuthLoginIn) -> AuthLoginOut:
    expected = configured_token_hash()
    if not expected:
        return AuthLoginOut(ok=True, required=False)
    if not token_matches(body.token, expected):
        raise HTTPException(401, "访问令牌无效")
    return AuthLoginOut(ok=True, required=True)
