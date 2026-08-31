"""Global UI/API access token: env inject + settings override."""

from __future__ import annotations

import hashlib
import hmac
import threading
from urllib.parse import parse_qs

from ..config import settings
from ..models import AppSettings, SessionLocal

_hash_lock = threading.Lock()
_cached_hash: str | None = None
_hash_loaded = False

MIN_TOKEN_LEN = 4
AUTH_HEADER = "authorization"
TOKEN_HEADER = "x-vulnhunter-token"
QUERY_PARAM = "access_token"


def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_row() -> AppSettings | None:
    with SessionLocal() as db:
        return db.query(AppSettings).first()


def clear_access_token_cache() -> None:
    """Drop the in-process hash cache (tests + settings updates)."""
    global _cached_hash, _hash_loaded
    with _hash_lock:
        _cached_hash = None
        _hash_loaded = False


def _hash_from_row(row: AppSettings | None) -> str:
    stored = getattr(row, "access_token_hash", None) if row is not None else None
    if stored is not None:
        return str(stored).strip()
    env = (settings.access_token or "").strip()
    return hash_token(env) if env else ""


def configured_token_hash(row: AppSettings | None = None) -> str:
    """SHA-256 hex of the active token, or empty if the gate is off.

    DB ``access_token_hash`` None = fall back to ``VULNHUNTER_ACCESS_TOKEN``.
    A stored hash (including after a settings change) overrides env.
    """
    global _cached_hash, _hash_loaded
    if row is not None:
        digest = _hash_from_row(row)
        with _hash_lock:
            _cached_hash = digest
            _hash_loaded = True
        return digest
    with _hash_lock:
        if _hash_loaded:
            return _cached_hash or ""
    digest = _hash_from_row(_load_row())
    with _hash_lock:
        _cached_hash = digest
        _hash_loaded = True
    return digest


def is_access_token_configured(row: AppSettings | None = None) -> bool:
    return bool(configured_token_hash(row))


def token_matches(presented: str, expected_hash: str) -> bool:
    if not expected_hash:
        return False
    raw = (presented or "").strip()
    if not raw:
        return False
    digest = hash_token(raw)
    return hmac.compare_digest(digest, expected_hash)


def extract_presented_token(headers: dict[str, str], query: dict[str, list[str]]) -> str:
    auth = (headers.get(AUTH_HEADER) or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    header_token = (headers.get(TOKEN_HEADER) or "").strip()
    if header_token:
        return header_token
    values = query.get(QUERY_PARAM) or []
    if values:
        return (values[0] or "").strip()
    return ""


def extract_token_from_scope(scope: dict) -> str:
    headers: dict[str, str] = {}
    for key, value in scope.get("headers") or []:
        headers[key.decode("latin-1").lower()] = value.decode("latin-1")
    raw_qs = scope.get("query_string") or b""
    query = parse_qs(raw_qs.decode("latin-1"), keep_blank_values=True)
    return extract_presented_token(headers, query)


def update_access_token_hash(row: AppSettings, current_token: str, new_token: str) -> None:
    """Verify current (when a token is already on) and store the new hash.

    Empty ``new_token`` clears the DB override so env is used again.
    """
    expected = configured_token_hash(row)
    current = (current_token or "").strip()
    new = (new_token or "").strip()
    if expected and not token_matches(current, expected):
        raise ValueError("当前令牌不正确")
    if not new:
        row.access_token_hash = None
        clear_access_token_cache()
        return
    if len(new) < MIN_TOKEN_LEN:
        raise ValueError(f"新令牌至少 {MIN_TOKEN_LEN} 个字符")
    row.access_token_hash = hash_token(new)
    clear_access_token_cache()
