from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app


_CST = timezone(timedelta(hours=8))


def _add_vuln(
    tmp_env,
    project_id: int,
    *,
    title: str,
    status: str,
    created_at: datetime,
) -> int:
    Session = tmp_env["Session"]
    Vuln = tmp_env["models"].Vuln
    with Session() as db:
        v = Vuln(
            project_id=project_id,
            title=title,
            vuln_type="sqli",
            severity="high",
            status=status,
            created_at=created_at,
        )
        db.add(v)
        db.commit()
        db.refresh(v)
        return v.id


def test_vuln_calendar_buckets_by_shanghai_day(tmp_env, project):
    # UTC 2026-08-24 16:30 → Shanghai 2026-08-25 00:30
    _add_vuln(
        tmp_env,
        project,
        title="confirmed-aug25",
        status="confirmed",
        created_at=datetime(2026, 8, 24, 16, 30, tzinfo=timezone.utc),
    )
    # UTC 2026-08-24 15:30 → Shanghai 2026-08-24 23:30
    _add_vuln(
        tmp_env,
        project,
        title="static-aug24",
        status="static_only",
        created_at=datetime(2026, 8, 24, 15, 30, tzinfo=timezone.utc),
    )
    _add_vuln(
        tmp_env,
        project,
        title="fp-aug25",
        status="false_positive",
        created_at=datetime(2026, 8, 25, 1, 0, tzinfo=_CST),
    )
    _add_vuln(
        tmp_env,
        project,
        title="pending-ignored",
        status="pending_review",
        created_at=datetime(2026, 8, 25, 12, 0, tzinfo=_CST),
    )
    _add_vuln(
        tmp_env,
        project,
        title="merged-ignored",
        status="merged",
        created_at=datetime(2026, 8, 25, 13, 0, tzinfo=_CST),
    )

    with TestClient(app) as client:
        bad = client.get("/api/vulns/calendar", params={"year": 2026, "month": 13})
        assert bad.status_code == 400

        body = client.get("/api/vulns/calendar", params={"year": 2026, "month": 8}).json()
        assert body["year"] == 2026
        assert body["month"] == 8
        by_date = {d["date"]: d for d in body["days"]}
        assert by_date["2026-08-24"] == {
            "date": "2026-08-24",
            "confirmed": 1,
            "false_positive": 0,
        }
        assert by_date["2026-08-25"] == {
            "date": "2026-08-25",
            "confirmed": 1,
            "false_positive": 1,
        }
        assert "2026-08-26" not in by_date

        day_list = client.get(
            "/api/vulns",
            params={"created_date": "2026-08-25"},
        ).json()
        titles = {row["title"] for row in day_list}
        assert "confirmed-aug25" in titles
        assert "fp-aug25" in titles
        assert "pending-ignored" in titles
        assert "static-aug24" not in titles

        bad_date = client.get("/api/vulns", params={"created_date": "2026-8-25"})
        assert bad_date.status_code == 400


def test_vuln_calendar_filters_by_project(tmp_env, project):
    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        other = models.Project(name="other", source_type="zip", status="recon", phase="recon")
        db.add(other)
        db.commit()
        db.refresh(other)
        other_id = other.id

    stamp = datetime(2026, 8, 10, 10, 0, tzinfo=_CST)
    _add_vuln(tmp_env, project, title="mine", status="confirmed", created_at=stamp)
    _add_vuln(tmp_env, other_id, title="theirs", status="false_positive", created_at=stamp)

    with TestClient(app) as client:
        body = client.get(
            "/api/vulns/calendar",
            params={"year": 2026, "month": 8, "project_id": project},
        ).json()
        by_date = {d["date"]: d for d in body["days"]}
        assert by_date["2026-08-10"] == {
            "date": "2026-08-10",
            "confirmed": 1,
            "false_positive": 0,
        }

        all_body = client.get("/api/vulns/calendar", params={"year": 2026, "month": 8}).json()
        all_by_date = {d["date"]: d for d in all_body["days"]}
        assert all_by_date["2026-08-10"] == {
            "date": "2026-08-10",
            "confirmed": 1,
            "false_positive": 1,
        }
