"""Sandbox path helpers for tools."""

from __future__ import annotations

import re
from pathlib import Path

from ..services.ingest import IGNORE_DIR_NAMES
from ..services.paths import (
    docs_dir,
    env_dir,
    old_vulns_dir,
    project_root,
    src_dir,
    vulns_dir,
    workspace_dir,
)


class SandboxError(Exception):
    pass


def resolve_under(root: Path, rel: str) -> Path:
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if ".." in Path(rel).parts:
        raise SandboxError("路径不允许包含 ..")
    target = (root / rel).resolve()
    root_resolved = root.resolve()
    if not str(target).startswith(str(root_resolved)):
        raise SandboxError(f"路径越界: {rel}")
    return target


def is_src_path(project_id: int, path: Path) -> bool:
    src = src_dir(project_id).resolve()
    try:
        path.resolve().relative_to(src)
        return True
    except ValueError:
        return False


def is_old_vulns_path(project_id: int, path: Path) -> bool:
    old = old_vulns_dir(project_id).resolve()
    try:
        path.resolve().relative_to(old)
        return True
    except ValueError:
        return False


def assert_readable(project_id: int, rel_or_abs: str) -> Path:
    """Resolve readable path under project; block old-vulns."""
    root = project_root(project_id).resolve()
    p = Path(rel_or_abs)
    if p.is_absolute():
        target = p.resolve()
        if not str(target).startswith(str(root)):
            raise SandboxError("绝对路径不在项目工作区内")
    else:
        # Prefer src, then project root
        rel = rel_or_abs.replace("\\", "/")
        if rel.startswith("src/"):
            target = resolve_under(src_dir(project_id), rel[4:])
        elif rel.startswith("docs/"):
            target = resolve_under(docs_dir(project_id), rel[5:])
        elif rel.startswith("workspace/"):
            target = resolve_under(workspace_dir(project_id), rel[10:])
        elif rel.startswith("vulns/"):
            target = resolve_under(vulns_dir(project_id), rel[6:])
        elif rel.startswith("env/"):
            target = resolve_under(env_dir(project_id), rel[4:])
        else:
            # default: relative to src
            candidate = src_dir(project_id) / rel
            if candidate.exists():
                target = candidate.resolve()
            else:
                target = resolve_under(root, rel)
    if is_old_vulns_path(project_id, target):
        raise SandboxError("历史漏洞目录仅允许 SearchOldVuln 访问，禁止 Read/Grep/Glob/Bash/PowerShell")
    return target


def assert_writable(project_id: int, rel: str) -> Path:
    """Write only under workspace / docs (not old-vulns) / vulns."""
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if rel.startswith("workspace/"):
        return resolve_under(workspace_dir(project_id), rel[10:])
    if rel.startswith("docs/old-vulns/") or rel == "docs/old-vulns":
        raise SandboxError("历史漏洞目录仅允许 WriteOldVuln 写入，禁止 Write/Bash/PowerShell 直接落盘")
    if rel.startswith("docs/"):
        target = resolve_under(docs_dir(project_id), rel[5:])
        return target
    if rel.startswith("vulns/"):
        return resolve_under(vulns_dir(project_id), rel[6:])
    if rel.startswith("env/"):
        return resolve_under(env_dir(project_id), rel[4:])
    # default write to workspace
    return resolve_under(workspace_dir(project_id), rel)


_DISK_FORMAT = re.compile(
    r"(?:^|[\s;&|])format(?:\.com)?(?:\s+/[a-z]+)*\s+[a-z]:",
    re.I,
)

# Recursive listing / tree-walk. Where-Object and -Exclude only filter output;
# Get-ChildItem -Recurse still descends into node_modules / target.
_LISTING_CMD = re.compile(
    r"(?:^|[\s;&(|])(?:(?:[\w.]+\\)?get-childitem|\bgci\b|\bls\b|\bdir\b)\b",
    re.I,
)
_PS_RECURSE = re.compile(r"-(?:recurse|depth)\b", re.I)
_GCI_DASH_R = re.compile(
    r"(?:^|[\s;&(|])(?:(?:[\w.]+\\)?get-childitem|\bgci\b)\b[\s\S]{0,400}(?<![\w-])-r(?![\w-])",
    re.I,
)
_DIR_S = re.compile(r"(?:^|[\s;&(|])dir\b[\s\S]{0,400}/[sS]\b", re.I)
_LS_CAP_R = re.compile(r"(?:^|[\s;&(|])ls\b[\s\S]{0,80}\s-[A-Za-z]*R\b")
_LS_DASH_R = re.compile(
    r"(?:^|[\s;&(|])ls\b[\s\S]{0,80}(?<![\w-])-r(?![\w-])",
    re.I,
)
_TREE_CMD = re.compile(r"(?:^|[\s;&(|])tree(?:\.com|\.exe)?\b", re.I)
_UNIX_FIND = re.compile(r'(?:^|[\s;&(|])find(?:\.exe)?\s+(?!["\'/])', re.I)
_FINDSTR_S = re.compile(r"(?:^|[\s;&(|])findstr\b[\s\S]{0,300}/[sS]\b", re.I)
_GREP_R = re.compile(
    r"(?:^|[\s;&(|])(?:e?grep|ggrep)\b[\s\S]{0,200}\s-[A-Za-z]*[rR][A-Za-z]*\b"
)
_FOR_R = re.compile(r"(?:^|[\s;&(|])for\s+/[rR]\b", re.I)
_SELECT_STRING_R = re.compile(
    r"(?:^|[\s;&(|])(?:select-string|\bsls\b)\b[\s\S]{0,800}-(?:recurse|depth)\b",
    re.I,
)

_UNBOUNDED_LISTING_HINT = (
    "禁止无限制递归列举/遍历。Get-ChildItem -Recurse/-Depth、ls -R、dir /s、find、tree "
    "会走进 node_modules/target 等目录；Where-Object 与 -Exclude 只过滤输出，不会跳过遍历。"
    "请改用 Glob，或只列一层："
    "Get-ChildItem -Path <单目录> -Directory（不要 -Recurse/-Depth），"
    f"并避开 {', '.join(sorted(IGNORE_DIR_NAMES))}。"
)


def unbounded_listing_reason(command: str) -> str | None:
    """Return a short label if the command would recursively walk the tree."""
    text = command or ""
    if _TREE_CMD.search(text):
        return "tree"
    if _UNIX_FIND.search(text):
        return "find"
    if _FINDSTR_S.search(text):
        return "findstr /s"
    if _GREP_R.search(text):
        return "grep -r"
    if _FOR_R.search(text):
        return "for /r"
    if _SELECT_STRING_R.search(text):
        return "Select-String -Recurse"
    if _DIR_S.search(text):
        return "dir /s"
    if _LS_CAP_R.search(text) or _LS_DASH_R.search(text):
        return "ls -R"
    if _LISTING_CMD.search(text) and _PS_RECURSE.search(text):
        return "Get-ChildItem -Recurse/-Depth"
    if _GCI_DASH_R.search(text):
        return "Get-ChildItem -r"
    return None


def block_dangerous_shell(command: str, project_id: int) -> None:
    lowered = (command or "").lower()
    banned = (
        "rm -rf /",
        "del /s /q",
        "rmdir /s",
        "remove-item -recurse",
        "shutdown",
        "mkfs",
    )
    for b in banned:
        if b in lowered:
            raise SandboxError(f"命令包含禁止模式: {b}")
    if _DISK_FORMAT.search(command or ""):
        raise SandboxError("命令包含禁止模式: format <盘符>")
    reason = unbounded_listing_reason(command)
    if reason:
        raise SandboxError(f"{_UNBOUNDED_LISTING_HINT} 命中: {reason}")
    # Block deleting project src or product root
    root = str(project_root(project_id).resolve()).lower().replace("\\", "/")
    src = str(src_dir(project_id).resolve()).lower().replace("\\", "/")
    if ("rm " in lowered or "del " in lowered or "remove-item" in lowered) and (
        src in lowered.replace("\\", "/") or root in lowered.replace("\\", "/")
    ):
        if "src" in lowered or "vulnhunter" in lowered:
            raise SandboxError("不允许删除项目源码或产品自身目录")
