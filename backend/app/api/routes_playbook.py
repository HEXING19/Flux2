from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.core.db import get_session
from app.playbook.schemas import PlaybookRunRequest, RoutineCheckBlockPreviewRequest, RoutineCheckBlockRequest
from app.playbook.service import playbook_service


router = APIRouter(prefix="/api/playbooks", tags=["playbook"])


@router.get("/templates")
def list_playbook_templates():
    return playbook_service.list_templates()


@router.post("/run")
def run_playbook(payload: PlaybookRunRequest, session: Session = Depends(get_session)):
    try:
        run = playbook_service.start_run(
            session,
            template_id=payload.template_id,
            params=payload.params,
            session_id=payload.session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    data = playbook_service.serialize_run(run)
    return {
        "run_id": run.id,
        "status": run.status,
        "partial_context": data.get("context", {}),
    }


@router.get("/runs/{run_id}")
def get_playbook_run(run_id: int, session: Session = Depends(get_session)):
    try:
        run = playbook_service.get_run_or_raise(session, run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return playbook_service.serialize_run(run)


@router.post("/routine-check/block-sources")
def routine_check_block_sources(payload: RoutineCheckBlockRequest, session: Session = Depends(get_session)):
    try:
        return playbook_service.block_malicious_sources(
            session,
            session_id=payload.session_id,
            ips=payload.ips,
            block_type=payload.block_type,
            reason=payload.reason,
            duration_hours=payload.duration_hours,
            device_id=payload.device_id,
            rule_name=payload.rule_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/routine-check/block-preview")
def routine_check_block_preview(payload: RoutineCheckBlockPreviewRequest, session: Session = Depends(get_session)):
    try:
        return playbook_service.preview_block_targets(
            session,
            session_id=payload.session_id,
            ips=payload.ips,
            block_type=payload.block_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
