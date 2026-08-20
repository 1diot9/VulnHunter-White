from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.services.docker_service import (
    ProjectRef,
    docker_service,
    match_container,
    match_image,
)


@pytest.fixture(autouse=True)
def _reset_docker_service():
    yield
    docker_service.reset()


def _ref(pid: int = 10, name: str = "halo") -> ProjectRef:
    return ProjectRef(
        id=pid,
        name=name,
        prefixes=(f"{name}-{pid}", f"vulnhunter-{pid}"),
        container_ids=("abc123def456",),
        container_names=(f"{name}-{pid}",),
    )


def test_match_container_by_name_and_sidecar():
    refs = [_ref(10, "halo"), _ref(101, "halo")]
    lab = match_container(name="halo-10", labels={}, image="halo-10:lab", refs=refs)
    assert lab is not None
    assert lab["kind"] == "lab"
    assert lab["project_id"] == 10
    side = match_container(name="halo-10-mysql", labels={}, image="mysql:8", refs=refs)
    assert side is not None
    assert side["kind"] == "sidecar"
    assert side["project_id"] == 10
    other = match_container(name="halo-101", labels={}, image="halo-101:lab", refs=refs)
    assert other is not None
    assert other["project_id"] == 101
    assert match_container(name="unrelated", labels={}, image="nginx", refs=refs) is None


def test_match_container_by_label_and_sandbox():
    refs = [_ref(7, "demo")]
    labeled = match_container(
        name="random-name",
        labels={"vulnhunter": "1", "vulnhunter.project": "7"},
        image="demo-7:lab",
        refs=refs,
    )
    assert labeled is not None
    assert labeled["project_id"] == 7
    sandbox = match_container(
        name="festive_sand",
        labels={"vulnhunter": "1"},
        image="vulnhunter/sandbox:latest",
        refs=refs,
    )
    assert sandbox is not None
    assert sandbox["kind"] == "sandbox"
    foreign = match_container(name="autopoc-x", labels={"autopoc": "1"}, image="x", refs=refs)
    assert foreign is None


def test_match_image_lab_sandbox_and_dependency():
    refs = [_ref(10, "halo")]
    lab = match_image(tags=["halo-10:lab"], labels={}, refs=refs)
    assert lab is not None
    assert lab["kind"] == "lab"
    assert lab["deletable"] is True
    sandbox = match_image(tags=["vulnhunter/sandbox:latest"], labels={}, refs=refs)
    assert sandbox is not None
    assert sandbox["kind"] == "sandbox"
    dep = match_image(tags=["mysql:8"], labels={}, refs=refs, used_by_owned=True)
    assert dep is not None
    assert dep["kind"] == "dependency"
    assert dep["deletable"] is False
    assert match_image(tags=["mysql:8"], labels={}, refs=refs, used_by_owned=False) is None
    labeled = match_image(tags=["custom:1"], labels={"vulnhunter": "1", "vulnhunter.project": "10"}, refs=refs)
    assert labeled is not None
    assert labeled["owned"] is True


class _FakeContainer:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "cid" + "0" * 60)
        self.short_id = kwargs.get("short_id", self.id[:12])
        self.name = kwargs["name"]
        self.status = kwargs.get("status", "running")
        self.labels = kwargs.get("labels", {})
        self.image = SimpleNamespace(tags=kwargs.get("tags", []), short_id="imgshort")
        self.attrs = {
            "Created": "2026-08-19T00:00:00Z",
            "Image": kwargs.get("image_id", "sha256:img"),
            "Config": {"Image": kwargs.get("image", "halo-10:lab")},
            "NetworkSettings": {
                "Ports": {"8080/tcp": [{"HostPort": "18080"}]} if kwargs.get("ports", True) else {}
            },
        }
        self._started = False
        self._stopped = False

    def start(self):
        self._started = True
        self.status = "running"

    def stop(self, timeout=10):  # noqa: ARG002
        self._stopped = True
        self.status = "exited"

    def reload(self):
        return None

    def remove(self, force=True):  # noqa: ARG002
        self.status = "removed"


class _FakeImage:
    def __init__(self, **kwargs):
        self.id = kwargs.get("id", "sha256:labimg")
        self.short_id = kwargs.get("short_id", "sha256:lab")
        self.tags = kwargs.get("tags", ["halo-10:lab"])
        self.attrs = {
            "Size": kwargs.get("size", 10 * 1024 * 1024),
            "Created": "2026-08-19T00:00:00Z",
            "Config": {"Labels": kwargs.get("labels", {})},
        }


class _FakeContainers:
    def __init__(self, items: list[_FakeContainer]):
        self.items = items
        self.list_calls: list[bool] = []

    def list(self, all=True):  # noqa: A002, ARG002
        self.list_calls.append(bool(all))
        if all:
            return list(self.items)
        return [c for c in self.items if c.status == "running"]

    def get(self, container_id: str):
        for item in self.items:
            if item.id == container_id or item.short_id == container_id or item.name == container_id:
                return item
        from docker.errors import NotFound

        raise NotFound("missing")


class _FakeImages:
    def __init__(self, items: list[_FakeImage]):
        self.items = items
        self.removed: list[str] = []

    def list(self, all=True):  # noqa: A002, ARG002
        return list(self.items)

    def get(self, image_id: str):
        for item in self.items:
            if item.id == image_id or item.short_id == image_id or image_id in item.tags:
                return item
        from docker.errors import NotFound

        raise NotFound("missing")

    def remove(self, image_id, force=False, noprune=False):  # noqa: ARG002
        self.removed.append(image_id)
        self.items = [i for i in self.items if i.id != image_id]


class _FakeClient:
    def __init__(self, containers: list[_FakeContainer], images: list[_FakeImage]):
        self.containers = _FakeContainers(containers)
        self.images = _FakeImages(images)

    def ping(self):
        return True


def _install_fake(monkeypatch, client: _FakeClient):
    docker_service.reset()
    docker_service._client = client
    monkeypatch.setattr(docker_service, "ping", lambda: True)


def test_list_containers_and_images_filters_owned(tmp_env, project, monkeypatch):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        row = db.get(Project, project)
        row.name = "halo"
        db.commit()

    lab = _FakeContainer(
        id="a" * 64,
        name=f"halo-{project}",
        image=f"halo-{project}:lab",
        tags=[f"halo-{project}:lab"],
        image_id="sha256:labimg",
        labels={"vulnhunter": "1", "vulnhunter.project": str(project)},
    )
    mysql = _FakeContainer(
        id="b" * 64,
        name=f"halo-{project}-mysql",
        image="mysql:8",
        tags=["mysql:8"],
        image_id="sha256:mysql",
        labels={"com.docker.compose.project": f"halo-{project}"},
    )
    foreign = _FakeContainer(
        id="c" * 64,
        name="autopoc-other",
        image="autopoc-x:1",
        tags=["autopoc-x:1"],
        image_id="sha256:foreign",
        labels={"autopoc": "1"},
    )
    images = [
        _FakeImage(id="sha256:labimg", tags=[f"halo-{project}:lab"], labels={"vulnhunter": "1"}),
        _FakeImage(id="sha256:mysql", tags=["mysql:8"]),
        _FakeImage(id="sha256:foreign", tags=["autopoc-x:1"]),
        _FakeImage(id="sha256:sandbox", tags=["vulnhunter/sandbox:latest"]),
    ]
    _install_fake(monkeypatch, _FakeClient([lab, mysql, foreign], images))

    from app.main import app

    with TestClient(app) as client:
        listed = client.get("/api/docker/containers")
        assert listed.status_code == 200
        names = {row["name"] for row in listed.json()}
        assert f"halo-{project}" in names
        assert f"halo-{project}-mysql" in names
        assert "autopoc-other" not in names
        assert listed.json()[0]["ports"]

        imgs = client.get("/api/docker/images")
        assert imgs.status_code == 200
        labels = {row["label"] for row in imgs.json()}
        assert f"halo-{project}:lab" in labels
        assert "mysql:8" in labels
        assert "vulnhunter/sandbox:latest" in labels
        assert "autopoc-x:1" not in labels
        mysql_row = next(row for row in imgs.json() if row["label"] == "mysql:8")
        assert mysql_row["kind"] == "dependency"
        assert mysql_row["deletable"] is False

        usage = client.get("/api/docker/images/usage")
        assert usage.status_code == 200
        assert usage.json()["image_count"] >= 3

        stopped = client.post(f"/api/docker/containers/{lab.id}/stop")
        assert stopped.status_code == 200
        assert lab._stopped is True

        refused = client.post("/api/docker/containers/missing/stop")
        assert refused.status_code in {404, 500}


def test_docker_unavailable_returns_503(tmp_env, monkeypatch):
    docker_service.reset()
    monkeypatch.setattr(docker_service, "ping", lambda: False)
    from app.main import app

    with TestClient(app) as client:
        assert client.get("/api/docker/containers").status_code == 503
        assert client.get("/api/docker/images").status_code == 503


def test_stop_batch_skips_foreign_container(tmp_env, project, monkeypatch):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        row = db.get(Project, project)
        row.name = "halo"
        db.commit()

    ours = _FakeContainer(id="a" * 64, name=f"halo-{project}", image=f"halo-{project}:lab")
    foreign = _FakeContainer(id="c" * 64, name="other", image="nginx")
    _install_fake(monkeypatch, _FakeClient([ours, foreign], []))
    from app.main import app

    with TestClient(app) as client:
        resp = client.post("/api/docker/containers/stop", json={"ids": [ours.id, foreign.id]})
        assert resp.status_code == 200
        by_id = {row["id"]: row for row in resp.json()["results"]}
        assert by_id[ours.id]["error"] is None
        assert by_id[foreign.id]["status"] == "skipped"


def test_list_images_scans_containers_once(tmp_env, project, monkeypatch):
    from app.models import Project, SessionLocal

    with SessionLocal() as db:
        row = db.get(Project, project)
        row.name = "halo"
        db.commit()

    lab = _FakeContainer(
        id="a" * 64,
        name=f"halo-{project}",
        image=f"halo-{project}:lab",
        tags=[f"halo-{project}:lab"],
        image_id="sha256:labimg",
    )
    client = _FakeClient(
        [lab],
        [_FakeImage(id="sha256:labimg", tags=[f"halo-{project}:lab"], labels={"vulnhunter": "1"})],
    )
    _install_fake(monkeypatch, client)
    docker_service.list_images()
    assert client.containers.list_calls == [True]
