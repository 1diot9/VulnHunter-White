"""List and manage Docker resources created by VulnHunter labs / sandbox."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import docker
from docker.errors import DockerException, NotFound
from docker.models.containers import Container
from docker.models.images import Image

from .lab import (
    LAB_LABEL_KEY,
    LAB_LABEL_VALUE,
    LAB_PROJECT_LABEL_KEY,
    lab_name_prefixes,
    load_env,
    name_matches_lab_prefix,
)
from .sandbox_exec import sandbox_image

logger = logging.getLogger(__name__)

KIND_LAB = "lab"
KIND_SIDECAR = "sidecar"
KIND_SANDBOX = "sandbox"
KIND_OTHER = "other"
KIND_DEPENDENCY = "dependency"


@dataclass(frozen=True)
class ProjectRef:
    id: int
    name: str
    prefixes: tuple[str, ...]
    container_ids: tuple[str, ...]
    container_names: tuple[str, ...]


def collect_project_refs() -> list[ProjectRef]:
    from ..models import Project, SessionLocal

    with SessionLocal() as db:
        rows = db.query(Project).all()
        items = [(int(p.id), str(p.name or "")) for p in rows]
    refs: list[ProjectRef] = []
    for pid, name in items:
        env = load_env(pid)
        ids: list[str] = []
        names: list[str] = []
        cid = str(env.get("container_id") or "").strip()
        cname = str(env.get("container_name") or "").strip().lstrip("/")
        if cid:
            ids.append(cid)
        if cname:
            names.append(cname)
        refs.append(
            ProjectRef(
                id=pid,
                name=name,
                prefixes=tuple(lab_name_prefixes(pid, project_name=name)),
                container_ids=tuple(ids),
                container_names=tuple(names),
            )
        )
    return refs


def _sandbox_refs() -> set[str]:
    raw = (sandbox_image() or "").strip().lower()
    if not raw:
        return {"vulnhunter/sandbox"}
    out = {raw, raw.split(":", 1)[0], "vulnhunter/sandbox"}
    return {item for item in out if item}


def is_sandbox_image(ref: str | None) -> bool:
    text = (ref or "").strip().lower()
    if not text:
        return False
    bare = text.split("@", 1)[0]
    for needle in _sandbox_refs():
        if bare == needle or bare.startswith(f"{needle}:") or needle in bare:
            return True
    return False


def _prefix_index(refs: list[ProjectRef]) -> list[tuple[str, ProjectRef]]:
    items: list[tuple[str, ProjectRef]] = []
    for ref in refs:
        for prefix in ref.prefixes:
            if prefix:
                items.append((prefix, ref))
    items.sort(key=lambda pair: len(pair[0]), reverse=True)
    return items


def _label_owned(labels: dict[str, str] | None) -> bool:
    labels = labels or {}
    return str(labels.get(LAB_LABEL_KEY) or "") == LAB_LABEL_VALUE


def _project_from_label(labels: dict[str, str] | None, refs: list[ProjectRef]) -> ProjectRef | None:
    labels = labels or {}
    raw = str(labels.get(LAB_PROJECT_LABEL_KEY) or "").strip()
    if not raw.isdigit():
        return None
    pid = int(raw)
    for ref in refs:
        if ref.id == pid:
            return ref
    return None


def match_container(
    *,
    name: str | None,
    labels: dict[str, str] | None,
    image: str | None,
    container_id: str | None = None,
    refs: list[ProjectRef] | None = None,
) -> dict[str, Any] | None:
    """Return ownership metadata if this container belongs to VulnHunter."""
    refs = refs or []
    labels = dict(labels or {})
    name = str(name or "").lstrip("/")
    image = str(image or "")
    cid = str(container_id or "")

    if is_sandbox_image(image):
        hit = _project_from_label(labels, refs)
        return {
            "owned": True,
            "kind": KIND_SANDBOX,
            "project_id": hit.id if hit else None,
            "project_name": hit.name if hit else None,
        }

    hit = _project_from_label(labels, refs)
    if hit is None:
        for prefix, ref in _prefix_index(refs):
            if name_matches_lab_prefix(name, prefix):
                hit = ref
                break
            compose = labels.get("com.docker.compose.project") or ""
            if compose and compose == prefix:
                hit = ref
                break
    if hit is None:
        for ref in refs:
            if name and name in ref.container_names:
                hit = ref
                break
            if cid and any(
                cid == item or cid.startswith(item) or item.startswith(cid)
                for item in ref.container_ids
                if item
            ):
                hit = ref
                break

    if hit is not None:
        kind = KIND_LAB
        for prefix in hit.prefixes:
            if name == prefix:
                kind = KIND_LAB
                break
            if name_matches_lab_prefix(name, prefix) and name != prefix:
                kind = KIND_SIDECAR
                break
        return {
            "owned": True,
            "kind": kind,
            "project_id": hit.id,
            "project_name": hit.name,
        }

    if _label_owned(labels):
        return {
            "owned": True,
            "kind": KIND_OTHER,
            "project_id": None,
            "project_name": None,
        }
    return None


def _tag_repo(tag: str) -> str:
    if ":" not in tag:
        return tag
    repo, _sep, _suffix = tag.rpartition(":")
    return repo or tag


def _is_lab_tag(tag: str, prefix: str) -> bool:
    repo = _tag_repo(tag)
    return tag.endswith(":lab") and name_matches_lab_prefix(repo, prefix)


def match_image(
    *,
    tags: list[str] | None,
    labels: dict[str, str] | None,
    refs: list[ProjectRef] | None = None,
    used_by_owned: bool = False,
) -> dict[str, Any] | None:
    """Return ownership metadata if this image belongs to VulnHunter labs."""
    refs = refs or []
    labels = dict(labels or {})
    tags = [str(t) for t in (tags or []) if t]
    labeled_project = _project_from_label(labels, refs)

    if any(is_sandbox_image(tag) for tag in tags):
        return {
            "owned": True,
            "kind": KIND_SANDBOX,
            "project_id": labeled_project.id if labeled_project else None,
            "project_name": labeled_project.name if labeled_project else None,
            "deletable": True,
        }

    lab_hit = labeled_project
    if lab_hit is None:
        for prefix, ref in _prefix_index(refs):
            if any(_is_lab_tag(tag, prefix) for tag in tags):
                lab_hit = ref
                break

    if lab_hit is not None and (
        _label_owned(labels)
        or any(_is_lab_tag(tag, prefix) for prefix in lab_hit.prefixes for tag in tags)
    ):
        return {
            "owned": True,
            "kind": KIND_LAB,
            "project_id": lab_hit.id,
            "project_name": lab_hit.name,
            "deletable": True,
        }

    if _label_owned(labels):
        return {
            "owned": True,
            "kind": KIND_OTHER,
            "project_id": labeled_project.id if labeled_project else None,
            "project_name": labeled_project.name if labeled_project else None,
            "deletable": True,
        }

    if used_by_owned:
        return {
            "owned": False,
            "kind": KIND_DEPENDENCY,
            "project_id": labeled_project.id if labeled_project else None,
            "project_name": labeled_project.name if labeled_project else None,
            "deletable": False,
        }
    return None


def _format_ports(ports: dict[str, Any] | None) -> list[str]:
    if not ports:
        return []
    mapped: list[str] = []
    for container_port, bindings in ports.items():
        cport = str(container_port).split("/", 1)[0]
        if not bindings:
            mapped.append(cport)
            continue
        for binding in bindings:
            host_port = binding.get("HostPort") or "?"
            mapped.append(f"{host_port}→{cport}")
    return mapped


def _container_image(container: Container) -> str:
    try:
        image = container.image
        tags = list(getattr(image, "tags", None) or [])
        if tags:
            return str(tags[0])
        short_id = getattr(image, "short_id", None)
        if short_id:
            return str(short_id)
    except Exception:  # noqa: BLE001
        pass
    attrs = container.attrs or {}
    config = attrs.get("Config") if isinstance(attrs.get("Config"), dict) else {}
    return str(config.get("Image") or "")


def _image_id(container: Container) -> str:
    attrs = container.attrs or {}
    image_id = attrs.get("Image")
    if image_id:
        return str(image_id)
    try:
        if container.image and container.image.id:
            return str(container.image.id)
    except Exception:  # noqa: BLE001
        pass
    return ""


class DockerService:
    def __init__(self) -> None:
        self._client: docker.DockerClient | None = None

    def reset(self) -> None:
        self._client = None

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def ping(self) -> bool:
        try:
            self.client.ping()
            return True
        except Exception:  # noqa: BLE001
            self._client = None
            return False

    def _require_client(self) -> docker.DockerClient:
        if not self.ping():
            raise DockerException("docker unavailable")
        return self.client

    def get_container(self, container_id: str) -> Container | None:
        try:
            return self.client.containers.get(container_id)
        except NotFound:
            return None
        except DockerException:
            return None

    def _describe_container(self, container: Container, refs: list[ProjectRef]) -> dict[str, Any] | None:
        labels = dict(container.labels or {})
        image = _container_image(container)
        meta = match_container(
            name=container.name,
            labels=labels,
            image=image,
            container_id=container.id,
            refs=refs,
        )
        if meta is None:
            return None
        ports = {}
        try:
            ports = (container.attrs or {}).get("NetworkSettings", {}).get("Ports") or {}
        except Exception:  # noqa: BLE001
            ports = {}
        return {
            "id": container.id,
            "short_id": container.short_id,
            "name": container.name or container.short_id,
            "status": container.status,
            "image": image,
            "ports": _format_ports(ports),
            "labels": labels,
            "kind": meta["kind"],
            "project_id": meta["project_id"],
            "project_name": meta["project_name"],
            "created": (container.attrs or {}).get("Created"),
        }

    def list_containers(
        self,
        refs: list[ProjectRef] | None = None,
        *,
        running_only: bool = False,
    ) -> list[dict[str, Any]]:
        refs = refs if refs is not None else collect_project_refs()
        client = self._require_client()
        containers = client.containers.list(all=not running_only)
        out: list[dict[str, Any]] = []
        for container in containers:
            item = self._describe_container(container, refs)
            if item is not None:
                out.append(item)
        out.sort(key=lambda row: (row.get("project_id") or 10**9, row.get("name") or "", row.get("id") or ""))
        return out

    def owned_container(self, container_id: str, refs: list[ProjectRef] | None = None) -> dict[str, Any] | None:
        refs = refs if refs is not None else collect_project_refs()
        container = self.get_container(container_id)
        if container is None:
            return None
        return self._describe_container(container, refs)

    def start(self, container_id: str) -> str:
        container = self.client.containers.get(container_id)
        if container.status != "running":
            container.start()
        container.reload()
        return container.status

    def stop(self, container_id: str) -> str:
        container = self.client.containers.get(container_id)
        if container.status == "running":
            container.stop(timeout=10)
        container.reload()
        return container.status

    def remove(self, container_id: str, *, force: bool = True) -> None:
        container = self.get_container(container_id)
        if container is not None:
            container.remove(force=force)

    def stop_many(self, container_ids: list[str], refs: list[ProjectRef] | None = None) -> list[dict[str, Any]]:
        refs = refs if refs is not None else collect_project_refs()
        results: list[dict[str, Any]] = []
        for cid in container_ids:
            try:
                if self.owned_container(cid, refs) is None:
                    results.append({"id": cid, "status": "skipped", "error": "not a vulnhunter container"})
                    continue
                status = self.stop(cid)
                results.append({"id": cid, "status": status, "error": None})
            except NotFound:
                results.append({"id": cid, "status": "absent", "error": "not found"})
            except Exception as exc:  # noqa: BLE001
                results.append({"id": cid, "status": "error", "error": str(exc)})
        return results

    def start_many(self, container_ids: list[str], refs: list[ProjectRef] | None = None) -> list[dict[str, Any]]:
        refs = refs if refs is not None else collect_project_refs()
        results: list[dict[str, Any]] = []
        for cid in container_ids:
            try:
                if self.owned_container(cid, refs) is None:
                    results.append({"id": cid, "status": "skipped", "error": "not a vulnhunter container"})
                    continue
                status = self.start(cid)
                results.append({"id": cid, "status": status, "error": None})
            except NotFound:
                results.append({"id": cid, "status": "absent", "error": "not found"})
            except Exception as exc:  # noqa: BLE001
                results.append({"id": cid, "status": "error", "error": str(exc)})
        return results

    def remove_stopped(self, refs: list[ProjectRef] | None = None) -> dict[str, Any]:
        refs = refs if refs is not None else collect_project_refs()
        removed: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []
        for item in self.list_containers(refs, running_only=False):
            if item.get("status") == "running":
                continue
            try:
                self.remove(item["id"], force=True)
                removed.append({"id": item["id"], "name": item["name"]})
            except Exception as exc:  # noqa: BLE001
                errors.append({"id": item.get("id") or "", "name": item.get("name") or "", "error": str(exc)})
        return {"removed_count": len(removed), "removed": removed, "errors": errors}

    def _owned_image_ids(self, refs: list[ProjectRef]) -> set[str]:
        ids: set[str] = set()
        try:
            containers = self.client.containers.list(all=True)
        except DockerException:
            return ids
        for container in containers:
            if self._describe_container(container, refs) is None:
                continue
            image_id = _image_id(container)
            if image_id:
                ids.add(image_id)
        return ids

    def _all_referenced_image_ids(self) -> set[str]:
        referenced: set[str] = set()
        for container in self.client.containers.list(all=True):
            image_id = _image_id(container)
            if image_id:
                referenced.add(image_id)
        return referenced

    def _describe_image(
        self,
        image: Image,
        refs: list[ProjectRef],
        owned_image_ids: set[str],
        referenced: set[str],
    ) -> dict[str, Any] | None:
        tags = list(image.tags or [])
        attrs = image.attrs or {}
        labels = {}
        config = attrs.get("Config") if isinstance(attrs.get("Config"), dict) else {}
        if isinstance(config.get("Labels"), dict):
            labels = {str(k): str(v) for k, v in config["Labels"].items() if k is not None}
        image_labels = attrs.get("Labels")
        if isinstance(image_labels, dict):
            labels.update({str(k): str(v) for k, v in image_labels.items() if k is not None})
        image_id = str(image.id or "")
        used_by_owned = image_id in owned_image_ids
        meta = match_image(tags=tags, labels=labels, refs=refs, used_by_owned=used_by_owned)
        if meta is None:
            return None
        size = int(attrs.get("Size") or 0)
        in_use = image_id in referenced
        return {
            "id": image_id,
            "short_id": image.short_id,
            "tags": tags,
            "label": tags[0] if tags else image.short_id,
            "status": "in_use" if in_use else ("dangling" if not tags else "unused"),
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 2),
            "kind": meta["kind"],
            "project_id": meta["project_id"],
            "project_name": meta["project_name"],
            "deletable": bool(meta["deletable"]) and not in_use,
            "in_use": in_use,
            "dangling": not tags,
            "created": attrs.get("Created"),
        }

    def list_images(self, refs: list[ProjectRef] | None = None) -> list[dict[str, Any]]:
        refs = refs if refs is not None else collect_project_refs()
        client = self._require_client()
        owned_ids = self._owned_image_ids(refs)
        referenced = self._all_referenced_image_ids()
        out: list[dict[str, Any]] = []
        for image in client.images.list(all=True):
            item = self._describe_image(image, refs, owned_ids, referenced)
            if item is not None:
                out.append(item)
        out.sort(key=lambda row: (row.get("kind") or "", row.get("label") or "", row.get("id") or ""))
        return out

    def image_usage(self, refs: list[ProjectRef] | None = None) -> dict[str, Any]:
        images = self.list_images(refs)
        total_bytes = sum(int(item.get("size_bytes") or 0) for item in images)
        dangling = sum(1 for item in images if item.get("dangling"))
        return {
            "image_count": len(images),
            "dangling_count": dangling,
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "total_gb": round(total_bytes / (1024**3), 2),
        }

    def owned_image(self, image_id: str, refs: list[ProjectRef] | None = None) -> dict[str, Any] | None:
        refs = refs if refs is not None else collect_project_refs()
        try:
            image = self.client.images.get(image_id)
        except NotFound:
            return None
        except DockerException:
            return None
        owned_ids = self._owned_image_ids(refs)
        referenced = self._all_referenced_image_ids()
        return self._describe_image(image, refs, owned_ids, referenced)

    def remove_images(self, image_ids: list[str], refs: list[ProjectRef] | None = None) -> list[dict[str, Any]]:
        refs = refs if refs is not None else collect_project_refs()
        results: list[dict[str, Any]] = []
        for image_id in image_ids:
            try:
                item = self.owned_image(image_id, refs)
                if item is None:
                    results.append({"id": image_id, "status": "skipped", "error": "not a vulnhunter image"})
                    continue
                if not item.get("deletable"):
                    reason = "镜像正在被容器使用" if item.get("in_use") else "官方依赖镜像不在此删除"
                    results.append({"id": image_id, "status": "skipped", "error": reason})
                    continue
                self.client.images.remove(item["id"], force=False, noprune=False)
                results.append({"id": image_id, "status": "removed", "error": None})
            except NotFound:
                results.append({"id": image_id, "status": "absent", "error": "not found"})
            except Exception as exc:  # noqa: BLE001
                results.append({"id": image_id, "status": "error", "error": str(exc)})
        return results

    def prune_unused(self, *, remove_stopped: bool = False, refs: list[ProjectRef] | None = None) -> dict[str, Any]:
        """Remove stopped lab containers (optional) and unused owned lab/sandbox images."""
        refs = refs if refs is not None else collect_project_refs()
        if not self.ping():
            return {
                "skipped": True,
                "reason": "docker unavailable",
                "containers_removed": 0,
                "images_deleted": 0,
                "freed_bytes": 0,
                "freed_mb": 0.0,
                "errors": ["docker unavailable"],
            }
        errors: list[str] = []
        containers_removed = 0
        if remove_stopped:
            removed = self.remove_stopped(refs)
            containers_removed = int(removed.get("removed_count") or 0)
            for err in removed.get("errors") or []:
                errors.append(f"container {err.get('name') or err.get('id')}: {err.get('error')}")
        images_deleted = 0
        freed_bytes = 0
        for item in self.list_images(refs):
            if not item.get("deletable"):
                continue
            if item.get("kind") not in {KIND_LAB, KIND_OTHER}:
                continue
            try:
                size = int(item.get("size_bytes") or 0)
                self.client.images.remove(item["id"], force=False, noprune=False)
                images_deleted += 1
                freed_bytes += size
            except Exception as exc:  # noqa: BLE001
                errors.append(f"image {item.get('label') or item.get('id')}: {exc}")
        return {
            "skipped": False,
            "reason": None,
            "containers_removed": containers_removed,
            "images_deleted": images_deleted,
            "freed_bytes": freed_bytes,
            "freed_mb": round(freed_bytes / (1024 * 1024), 2),
            "errors": errors,
        }


docker_service = DockerService()
