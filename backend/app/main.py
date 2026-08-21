from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import docker, projects, settings, vulns
from .models import init_db
from .services.shutdown import install_signal_bridge, reset as reset_shutdown
from .tools import register_all_tools

app = FastAPI(title="VulnHunter", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(projects.router)
app.include_router(vulns.router)
app.include_router(settings.router)
app.include_router(docker.router)


@app.on_event("startup")
def on_startup() -> None:
    reset_shutdown()
    init_db()
    register_all_tools()
    install_signal_bridge()
    from .services.pipeline import recover_inflight_projects

    recover_inflight_projects()
    from .services.cli_tool_index import start_cli_tool_scanner

    start_cli_tool_scanner()


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "VulnHunter"}
