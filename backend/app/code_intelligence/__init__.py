"""Code Intelligence: source + bytecode graph queries for Worker / Reviewer.

Backends: CodeGraph (src/) and Jar Analyzer (MarkBusinessJar business jars).
Agent tools never talk to SQLite; Recon only chooses backends via MarkCodeIntel.
"""

from .service import (
    CODE_INTEL_PHASE,
    STATUSES,
    code_intel_choice_ready,
    code_intel_settled,
    mark_code_intel,
    mark_stale_if_source_changed,
    metadata_payload,
    request_rebuild,
    request_ui,
    requested_backends,
    run_build,
    status_payload,
)
from .query import callees, callers, find_symbol, trace

__all__ = [
    "CODE_INTEL_PHASE",
    "STATUSES",
    "callees",
    "callers",
    "code_intel_choice_ready",
    "code_intel_settled",
    "find_symbol",
    "mark_code_intel",
    "mark_stale_if_source_changed",
    "metadata_payload",
    "request_rebuild",
    "request_ui",
    "requested_backends",
    "run_build",
    "status_payload",
    "trace",
]
