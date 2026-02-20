from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.core.db import get_session
from app.models.schemas import ApprovalDecisionIn, WorkflowConfigIn, WorkflowRunTrigger
from app.workflow.scheduler import reload_jobs
from app.workflow.service import workflow_service


router = APIRouter(prefix="/api/workflows", tags=["workflow"])


@router.get("")
def list_workflows(session: Session = Depends(get_session)):
    rows = workflow_service.list_workflows(session)
    return [
        {
            "id": r.id,
            "name": r.name,
            "cron_expr": r.cron_expr,
            "enabled": r.enabled,
            "levels": [int(x) for x in r.levels.split(",") if x],
            "require_approval": r.require_approval,
            "webhook_url": r.webhook_url,
        }
        for r in rows
    ]


@router.post("")
def upsert_workflow(payload: WorkflowConfigIn, session: Session = Depends(get_session)):
    wf = workflow_service.create_or_update_workflow(session, payload.model_dump())
    reload_jobs()
    return {
        "id": wf.id,
        "name": wf.name,
        "cron_expr": wf.cron_expr,
        "enabled": wf.enabled,
        "levels": [int(x) for x in wf.levels.split(",") if x],
        "require_approval": wf.require_approval,
    }


@router.post("/run")
def trigger_run(payload: WorkflowRunTrigger, session: Session = Depends(get_session)):
    try:
        run = workflow_service.run_workflow(session, payload.workflow_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "run_id": run.id,
        "status": run.status,
        "workflow_id": run.workflow_id,
        "context": json.loads(run.context_json) if run.context_json else None,
    }


@router.get("/approvals")
def list_approvals(session: Session = Depends(get_session)):
    rows = workflow_service.list_approvals(session)
    return [
        {
            "id": r.id,
            "workflow_run_id": r.workflow_run_id,
            "title": r.title,
            "payload": json.loads(r.payload_json),
            "status": r.status,
            "decision": r.decision,
            "reviewer": r.reviewer,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.post("/approvals/{approval_id}/decision")
def decide_approval(approval_id: int, payload: ApprovalDecisionIn, session: Session = Depends(get_session)):
    try:
        result = workflow_service.decide_approval(
            session,
            approval_id,
            decision=payload.decision,
            reviewer=payload.reviewer,
            comment=payload.comment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return result
