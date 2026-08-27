from __future__ import annotations

import pytest

from app.services.paths import ensure_project_dirs, old_vulns_dir, src_dir
from app.tools.sandbox import (
    SandboxError,
    assert_readable,
    assert_writable,
    block_dangerous_shell,
    unbounded_listing_reason,
)


def test_readable_src(project):
    p = assert_readable(project, "src/app/Main.java")
    assert p.exists()
    p2 = assert_readable(project, "app/Main.java")
    assert p2.exists()


def test_block_old_vulns_read(project):
    old = old_vulns_dir(project)
    old.mkdir(parents=True, exist_ok=True)
    f = old / "cve.md"
    f.write_text("---\ntitle: t\nsummary: s\n---\nbody\n", encoding="utf-8")
    with pytest.raises(SandboxError, match="SearchOldVuln"):
        assert_readable(project, "docs/old-vulns/cve.md")


def test_block_old_vulns_write(project):
    with pytest.raises(SandboxError, match="WriteOldVuln"):
        assert_writable(project, "docs/old-vulns/cve.md")


def test_writable_workspace(project):
    p = assert_writable(project, "workspace/note.txt")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("ok", encoding="utf-8")
    assert p.exists()


def test_reject_path_traversal(project):
    with pytest.raises(SandboxError):
        assert_writable(project, "workspace/../../etc/passwd")


def test_block_dangerous_shell(project):
    with pytest.raises(SandboxError):
        block_dangerous_shell("rm -rf /", project)
    block_dangerous_shell("echo hello", project)  # should not raise


def test_allow_docker_format_flag(project):
    block_dangerous_shell('docker ps --filter "name=x" --format "{{.ID}} {{.Status}}"', project)
    block_dangerous_shell("# the handler uses a different format for CSRF", project)


def test_block_disk_format(project):
    with pytest.raises(SandboxError, match="format"):
        block_dangerous_shell("format c:", project)


@pytest.mark.parametrize(
    "cmd",
    [
        'Get-ChildItem -Path "src" -Directory -Recurse -Depth 4',
        "Get-ChildItem src -Recurse",
        'Get-ChildItem -Path "src" -Directory -Recurse -Depth 4 | Where-Object { $_.Name -ne "node_modules" }',
        "gci src -Depth 3",
        "gci src -r",
        "ls -Recurse src",
        "ls -R src",
        "dir /s src",
        "find src -type d",
        "find . -name *.java",
        "tree src",
        "grep -r TODO src",
        "findstr /s /i login *",
        "Select-String -Path src -Pattern foo -Recurse",
        "for /r src %i in (*.java) do @echo %i",
    ],
)
def test_block_unbounded_listing(project, cmd):
    assert unbounded_listing_reason(cmd)
    with pytest.raises(SandboxError, match="递归"):
        block_dangerous_shell(cmd, project)


@pytest.mark.parametrize(
    "cmd",
    [
        'Get-ChildItem -Path "src" -Directory',
        "gci src",
        "ls src",
        "ls -la src",
        "dir src",
        "echo hello",
        "Get-Content src/app/Main.java",
        'findstr /i login src\\app\\Main.java',
        'find "login" src\\app\\Main.java',
        'grep TODO src/app/Main.java',
        "# Find site ID for admin workspace\nWrite-Host ok",
        'Write-Output "Could not find CSRF token in login page"',
        "$tokenMatch = [regex]::Match($loginPage, 'name=\"token\"')",
    ],
)
def test_allow_shallow_listing_and_search(project, cmd):
    assert unbounded_listing_reason(cmd) is None
    block_dangerous_shell(cmd, project)
