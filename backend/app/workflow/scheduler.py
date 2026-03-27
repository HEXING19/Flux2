from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlmodel import select

from app.core.validation import validate_cron_expr
from app.core.db import session_scope
from app.models.db_models import WorkflowConfig

from .service import run_workflow_job


scheduler = BackgroundScheduler(timezone="Asia/Shanghai")


def _parse_cron_expr(expr: str) -> CronTrigger:
    parts = validate_cron_expr(expr).split()
    minute, hour, day, month, day_of_week = parts
    return CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)


def reload_jobs() -> None:
    scheduler.remove_all_jobs()
    with session_scope() as session:
        workflows = session.exec(select(WorkflowConfig).where(WorkflowConfig.enabled == True)).all()  # noqa: E712
        for wf in workflows:
            try:
                trigger = _parse_cron_expr(wf.cron_expr)
                scheduler.add_job(
                    run_workflow_job,
                    trigger=trigger,
                    args=[wf.id],
                    id=f"workflow-{wf.id}",
                    replace_existing=True,
                )
            except Exception:
                continue


def start_scheduler() -> None:
    if scheduler.running:
        return
    reload_jobs()
    scheduler.start()


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
