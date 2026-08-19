from fastapi import APIRouter, HTTPException, Query

from ..schemas import (
    DockerActionBatchOut,
    DockerActionItemOut,
    DockerContainerOut,
    DockerIdList,
    DockerImageOut,
    DockerImagePruneRequest,
    DockerImagePruneResult,
    DockerImageUsageOut,
)
from ..services.docker_service import collect_project_refs, docker_service

router = APIRouter(prefix="/api/docker", tags=["docker"])


def _ensure_docker() -> None:
    if not docker_service.ping():
        raise HTTPException(503, "docker unavailable")


@router.get("/containers", response_model=list[DockerContainerOut])
def list_containers(running_only: bool = Query(False, description="仅返回运行中的容器")):
    _ensure_docker()
    try:
        items = docker_service.list_containers(collect_project_refs(), running_only=running_only)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(503, f"docker error: {exc}") from exc
    return [DockerContainerOut.model_validate(item) for item in items]


@router.post("/containers/stop", response_model=DockerActionBatchOut)
def stop_containers_batch(body: DockerIdList):
    """批量停止本平台靶场 / 沙箱容器。须注册在 {container_id} 路由之前。"""
    _ensure_docker()
    results = docker_service.stop_many(body.ids)
    return DockerActionBatchOut(results=[DockerActionItemOut.model_validate(r) for r in results])


@router.post("/containers/start", response_model=DockerActionBatchOut)
def start_containers_batch(body: DockerIdList):
    _ensure_docker()
    results = docker_service.start_many(body.ids)
    return DockerActionBatchOut(results=[DockerActionItemOut.model_validate(r) for r in results])


@router.post("/containers/{container_id}/stop", response_model=DockerActionItemOut)
def stop_container_by_id(container_id: str):
    _ensure_docker()
    if docker_service.owned_container(container_id) is None:
        raise HTTPException(404, "vulnhunter container not found")
    try:
        status = docker_service.stop(container_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, str(exc)) from exc
    return DockerActionItemOut(id=container_id, status=status)


@router.post("/containers/{container_id}/start", response_model=DockerActionItemOut)
def start_container_by_id(container_id: str):
    _ensure_docker()
    if docker_service.owned_container(container_id) is None:
        raise HTTPException(404, "vulnhunter container not found")
    try:
        status = docker_service.start(container_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, str(exc)) from exc
    return DockerActionItemOut(id=container_id, status=status)


@router.get("/images", response_model=list[DockerImageOut])
def list_images():
    _ensure_docker()
    try:
        items = docker_service.list_images(collect_project_refs())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(503, f"docker error: {exc}") from exc
    return [DockerImageOut.model_validate(item) for item in items]


@router.get("/images/usage", response_model=DockerImageUsageOut)
def images_usage():
    _ensure_docker()
    try:
        return DockerImageUsageOut.model_validate(docker_service.image_usage())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(503, f"docker error: {exc}") from exc


@router.post("/images/remove", response_model=DockerActionBatchOut)
def remove_images(body: DockerIdList):
    _ensure_docker()
    results = docker_service.remove_images(body.ids)
    return DockerActionBatchOut(results=[DockerActionItemOut.model_validate(r) for r in results])


@router.post("/images/prune", response_model=DockerImagePruneResult)
def prune_images(body: DockerImagePruneRequest | None = None):
    """清理未使用的自建靶场 / 沙箱镜像；可选先删除已停止的本平台容器。"""
    body = body or DockerImagePruneRequest()
    result = docker_service.prune_unused(remove_stopped=bool(body.remove_stopped))
    if result.get("skipped") and result.get("reason") == "docker unavailable":
        raise HTTPException(503, "docker unavailable")
    return DockerImagePruneResult.model_validate(result)
