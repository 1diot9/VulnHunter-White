"""Code Intelligence: source-graph queries for Worker / Reviewer.

First backend is CodeGraph (source only). Agent tools never talk to SQLite.
"""

from .service import (
    CODE_INTEL_PHASE,
    STATUSES,
    code_intel_settled,
    mark_stale_if_source_changed,
    metadata_payload,
    request_rebuild,
    request_ui,
    run_build,
    status_payload,
)
from .query import callees, callers, find_symbol, trace

__all__ = [
    "CODE_INTEL_PHASE",
    "STATUSES",
    "callees",
    "callers",
    "code_intel_settled",
    "find_symbol",
    "mark_stale_if_source_changed",
    "metadata_payload",
    "request_rebuild",
    "request_ui",
    "run_build",
    "status_payload",
    "trace",
]
