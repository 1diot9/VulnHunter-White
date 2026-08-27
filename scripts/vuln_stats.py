"""Print a Markdown table of audit projects and confirmed vuln counts.

Manual CLI only; does not touch the web app. Counts match the project list
「确认」number: status in confirmed / static_only (not pending, FP, or merged).

From repo root:  scripts\\vuln-stats.cmd
From backend:    vuln-stats.cmd
Unix:            sh scripts/vuln-stats.sh
Or:              backend/.venv/Scripts/python ../scripts/vuln_stats.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

CONFIRMED_STATUSES = ("confirmed", "static_only")


def collect_rows(db) -> list[tuple[str, int]]:
    from sqlalchemy import func

    from app.models import Project, Vuln

    count_map = dict(
        db.query(Vuln.project_id, func.count(Vuln.id))
        .filter(Vuln.status.in_(CONFIRMED_STATUSES))
        .group_by(Vuln.project_id)
        .all()
    )
    projects = db.query(Project).order_by(Project.id).all()
    name_counts: dict[str, int] = {}
    for project in projects:
        raw = (project.name or "").strip() or f"#{project.id}"
        name_counts[raw] = name_counts.get(raw, 0) + 1

    rows: list[tuple[str, int]] = []
    for project in projects:
        raw = (project.name or "").strip() or f"#{project.id}"
        label = f"{raw} (#{project.id})" if name_counts[raw] > 1 else raw
        rows.append((label, int(count_map.get(project.id, 0))))
    return rows


def _cell(text: str) -> str:
    return str(text).replace("\r\n", " ").replace("\n", " ").replace("|", "\\|")


def render_markdown(rows: list[tuple[str, int]]) -> str:
    lines = [
        "| 审计项目 | 产出的漏洞数量 |",
        "| --- | ---: |",
    ]
    total = 0
    for name, count in rows:
        total += count
        lines.append(f"| {_cell(name)} | {count} |")
    lines.append(f"| 合计 | {total} |")
    return "\n".join(lines) + "\n"


def resolve_output_path(raw: str) -> Path:
    return Path(raw).expanduser().resolve()


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="按审计项目统计已确认漏洞数，输出 Markdown 表格")
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="写入文件（UTF-8）；省略则打印到标准输出",
    )
    args = parser.parse_args(argv)

    from app.config import DB_PATH
    from app.models import SessionLocal

    if not DB_PATH.is_file():
        print(f"找不到数据库：{DB_PATH}", file=sys.stderr)
        return 1

    with SessionLocal() as db:
        table = render_markdown(collect_rows(db))

    _configure_stdio()
    if args.output:
        path = resolve_output_path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(table, encoding="utf-8")
        print(f"输出目录：{path.parent}")
    else:
        sys.stdout.write(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
