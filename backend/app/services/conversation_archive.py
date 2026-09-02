"""Archive the latest AgentLoop checkpoint per log sub-phase for user-initiated continue."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..agent.checkpoint import LoopCheckpoint, checkpoint_exists, load_checkpoint
from .paths import last_conversation_dir, steer_dir


# Frontend log tab -> DB phase(s); first is primary for archive key.
LOG_PHASE_DB_PHASES: dict[str, tuple[str, ...]] = {
    "recon-map": ("recon",),
    "recon-source-ext": ("recon-source-ext",),
    "recon-old-vuln": ("recon-old-vuln-ghsa", "recon-old-vuln"),
    "recon-mark": ("recon-mark",),
    "code-intel": ("code_intel",),
    "mine": ("worker",),
    "worker": ("worker",),
    "fast": ("fast-worker", "sink-triage"),
    "fast-worker": ("fast-worker", "sink-triage"),
    "bypass": ("bypass-worker",),
    "bypass-worker": ("bypass-worker",),
    "unconstrained": ("unconstrained-worker",),
    "unconstrained-worker": ("unconstrained-worker",),
    "fix": ("fix",),
    "reviewer-lab": ("reviewer-lab",),
    "reviewer-review": ("reviewer",),
    "verifier": ("verifier",),
    "attack_chain": ("attack_chain",),
}

DB_PHASE_TO_LOG_PHASE: dict[str, str] = {
    "recon": "recon-map",
    "recon-source-ext": "recon-source-ext",
    "recon-old-vuln": "recon-old-vuln",
    "recon-old-vuln-ghsa": "recon-old-vuln",
    "recon-mark": "recon-mark",
    "code_intel": "code-intel",
    "worker": "mine",
    "fast-worker": "fast",
    "sink-triage": "fast",
    "bypass-worker": "bypass",
    "unconstrained-worker": "unconstrained",
    "fix": "fix",
    "reviewer-lab": "reviewer-lab",
    "reviewer": "reviewer-review",
    "verifier": "verifier",
    "attack_chain": "attack_chain",
}


def normalize_log_phase(raw: str) -> str:
    key = (raw or "").strip().replace("_", "-")
    aliases = {
        "recon": "recon-map",
        "reconmap": "recon-map",
        "recon-map": "recon-map",
        "recon-source-ext": "recon-source-ext",
        "reconsourceext": "recon-source-ext",
        "recon-old-vuln": "recon-old-vuln",
        "reconoldvuln": "recon-old-vuln",
        "recon-mark": "recon-mark",
        "reconmark": "recon-mark",
        "code-intel": "code-intel",
        "codeintel": "code-intel",
        "mine": "mine",
        "worker": "mine",
        "fast": "fast",
        "fast-worker": "fast",
        "sink-triage": "fast",
        "bypass": "bypass",
        "bypass-worker": "bypass",
        "unconstrained": "unconstrained",
        "unconstrained-worker": "unconstrained",
        "fix": "fix",
        "reviewer-lab": "reviewer-lab",
        "reviewerlab": "reviewer-lab",
        "reviewer-review": "reviewer-review",
        "reviewer": "reviewer-review",
        "verifier": "verifier",
        "attack-chain": "attack_chain",
        "attack_chain": "attack_chain",
    }
    return aliases.get(key, key)


def log_phase_to_db_phases(log_phase: str) -> tuple[str, ...]:
    lp = normalize_log_phase(log_phase)
    return LOG_PHASE_DB_PHASES.get(lp, (lp,))


def db_phase_to_log_phase(db_phase: str) -> str:
    return DB_PHASE_TO_LOG_PHASE.get((db_phase or "").strip(), normalize_log_phase(db_phase))


def _archive_path(project_id: int, log_phase: str) -> Path:
    lp = normalize_log_phase(log_phase)
    d = last_conversation_dir(project_id)
    return d / f"{lp.replace('/', '_')}.json"


def archive_checkpoint(project_id: int, db_phase: str, cp: LoopCheckpoint) -> Path | None:
    if not cp.messages:
        return None
    log_phase = db_phase_to_log_phase(db_phase)
    path = _archive_path(project_id, log_phase)
    payload = cp.to_dict()
    payload["archived_from_db_phase"] = db_phase
    payload["log_phase"] = log_phase
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)
    return path


def load_archived(project_id: int, log_phase: str) -> LoopCheckpoint | None:
    path = _archive_path(project_id, log_phase)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not data.get("messages"):
        return None
    return LoopCheckpoint.from_dict(data)


def clear_archived(project_id: int, log_phase: str) -> None:
    path = _archive_path(project_id, log_phase)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def has_archived(project_id: int, log_phase: str) -> bool:
    return _archive_path(project_id, log_phase).is_file()


def ensure_steer_dir(project_id: int) -> Path:
    return steer_dir(project_id)
