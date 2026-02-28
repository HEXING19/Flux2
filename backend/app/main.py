from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlmodel import select

from app.api.routes_auth import router as auth_router
from app.api.routes_chat import router as chat_router
from app.api.routes_config import router as config_router
from app.api.routes_playbook import router as playbook_router
from app.api.routes_workflow import router as workflow_router
from app.api.routes_safety_gate import router as safety_gate_router
from app.core.db import init_db, session_scope
from app.models.db_models import ProviderConfig
from app.workflow.scheduler import start_scheduler, stop_scheduler


app = FastAPI(title="Flux XDR", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(config_router)
app.include_router(chat_router)
app.include_router(playbook_router)
app.include_router(workflow_router)
app.include_router(safety_gate_router)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    with session_scope() as session:
        deprecated_rows = session.exec(select(ProviderConfig).where(ProviderConfig.provider == "mock")).all()
        for row in deprecated_rows:
            session.delete(row)
    start_scheduler()


@app.on_event("shutdown")
def on_shutdown() -> None:
    stop_scheduler()


frontend_dir = Path(__file__).resolve().parents[2] / "frontend"
if frontend_dir.exists():
    app.mount("/assets", StaticFiles(directory=frontend_dir), name="assets")


@app.get("/")
def root() -> FileResponse:
    return FileResponse(frontend_dir / "index.html")
