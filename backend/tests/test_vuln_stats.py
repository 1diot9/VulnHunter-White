from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load_vuln_stats():
    spec = importlib.util.spec_from_file_location("vuln_stats", SCRIPTS / "vuln_stats.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _add_vuln(tmp_env, project_id: int, title: str, status: str) -> None:
    Session = tmp_env["Session"]
    Vuln = tmp_env["models"].Vuln
    with Session() as db:
        db.add(
            Vuln(
                project_id=project_id,
                title=title,
                vuln_type="sqli",
                severity="high",
                status=status,
            )
        )
        db.commit()


def test_collect_rows_counts_confirmed_only(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        other = models.Project(name="other", source_type="zip", status="completed", phase="done")
        db.add(other)
        db.commit()
        db.refresh(other)
        other_id = other.id

    _add_vuln(tmp_env, project, "ok", "confirmed")
    _add_vuln(tmp_env, project, "static", "static_only")
    _add_vuln(tmp_env, project, "fp", "false_positive")
    _add_vuln(tmp_env, project, "pending", "pending_review")
    _add_vuln(tmp_env, project, "merged", "merged")
    _add_vuln(tmp_env, other_id, "none", "confirmed")

    mod = _load_vuln_stats()
    with Session() as db:
        rows = mod.collect_rows(db)
    assert rows == [("demo", 2), ("other", 1)]

    md = mod.render_markdown(rows)
    assert md.startswith("| 审计项目 | 产出的漏洞数量 |")
    assert "| demo | 2 |" in md
    assert "| other | 1 |" in md
    assert md.strip().endswith("| 合计 | 3 |")


def test_render_escapes_pipes_and_disambiguates_names(tmp_env):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        a = models.Project(name="dup|name", source_type="zip")
        b = models.Project(name="dup|name", source_type="zip")
        db.add_all([a, b])
        db.commit()
        db.refresh(a)
        db.refresh(b)
        a_id, b_id = a.id, b.id

    _add_vuln(tmp_env, a_id, "one", "confirmed")

    mod = _load_vuln_stats()
    with Session() as db:
        rows = mod.collect_rows(db)
    assert rows == [(f"dup|name (#{a_id})", 1), (f"dup|name (#{b_id})", 0)]
    md = mod.render_markdown(rows)
    assert "| dup\\|name (#" in md
    assert "| 合计 | 1 |" in md


def test_resolve_output_path_is_absolute(tmp_path):
    mod = _load_vuln_stats()
    path = mod.resolve_output_path(str(tmp_path / "stats.md"))
    assert path.is_absolute()
    assert path.name == "stats.md"
    assert path.parent == tmp_path.resolve()
