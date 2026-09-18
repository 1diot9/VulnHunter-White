"""Structured short-result queries over Code Intelligence backends (via Resolver)."""

from __future__ import annotations

from .resolver import callees, callers, find_symbol, trace
from .query_codegraph import EDGE_LIMIT, OUTPUT_MAX_CHARS, SYMBOL_LIMIT, TRACE_LIMIT

__all__ = [
    "EDGE_LIMIT",
    "OUTPUT_MAX_CHARS",
    "SYMBOL_LIMIT",
    "TRACE_LIMIT",
    "callees",
    "callers",
    "find_symbol",
    "trace",
]
