"""ASGI middleware: require the global access token for API and docs."""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .services.access_token import configured_token_hash, extract_token_from_scope, token_matches

# Health + unlock stay public so the frontend can show the gate and start scripts can probe.
_PUBLIC = frozenset(
    {
        ("GET", "/api/health"),
        ("GET", "/api/auth/status"),
        ("POST", "/api/auth/login"),
    }
)


class AccessTokenMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = (scope.get("method") or "").upper()
        path = scope.get("path") or ""
        if method == "OPTIONS" or (method, path) in _PUBLIC:
            await self.app(scope, receive, send)
            return
        expected = configured_token_hash()
        if not expected:
            await self.app(scope, receive, send)
            return
        presented = extract_token_from_scope(scope)
        if token_matches(presented, expected):
            await self.app(scope, receive, send)
            return
        detail = "需要访问令牌" if not presented else "访问令牌无效"
        response = JSONResponse(
            {"detail": detail},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="VulnHunter"'},
        )
        await response(scope, receive, send)
