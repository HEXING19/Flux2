from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import httpx
from sqlmodel import Session, select

from app.core.context import context_manager
from app.core.db import session_scope
from app.core.payload import approval_payload, text_payload
from app.core.requester import get_requester_from_credential
from app.llm.router import LLMRouter
from app.models.db_models import ApprovalRequest, WorkflowConfig, WorkflowRun, XDRCredential
from app.skills.registry import SkillRegistry

from .engine import PipelineNode, WorkflowEngine


class WorkflowService:
    def __init__(self):
        self.engine = WorkflowEngine(max_workers=6)

    def _load_runtime(self, session: Session):
        credential = session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
        requester = get_requester_from_credential(credential)
        registry = SkillRegistry(requester, context_manager)
        return requester, registry

    def create_or_update_workflow(self, session: Session, payload: dict[str, Any]) -> WorkflowConfig:
        workflow_id = payload.get("id")
        if workflow_id:
            wf = session.get(WorkflowConfig, workflow_id)
            if not wf:
                raise ValueError("workflow not found")
            wf.name = payload["name"]
            wf.cron_expr = payload["cron_expr"]
            wf.enabled = payload.get("enabled", True)
            wf.levels = ",".join(str(x) for x in payload.get("levels", [3, 4]))
            wf.require_approval = payload.get("require_approval", True)
            wf.webhook_url = payload.get("webhook_url")
            wf.updated_at = datetime.utcnow()
            session.add(wf)
            session.commit()
            session.refresh(wf)
            return wf

        wf = WorkflowConfig(
            name=payload["name"],
            cron_expr=payload["cron_expr"],
            enabled=payload.get("enabled", True),
            levels=",".join(str(x) for x in payload.get("levels", [3, 4])),
            require_approval=payload.get("require_approval", True),
            webhook_url=payload.get("webhook_url"),
        )
        session.add(wf)
        session.commit()
        session.refresh(wf)
        return wf

    def list_workflows(self, session: Session) -> list[WorkflowConfig]:
        return session.exec(select(WorkflowConfig).order_by(WorkflowConfig.id.desc())).all()

    def run_workflow(self, session: Session, workflow_id: int, trigger_type: str = "manual") -> WorkflowRun:
        wf = session.get(WorkflowConfig, workflow_id)
        if not wf:
            raise ValueError("workflow not found")

        requester, registry = self._load_runtime(session)
        levels = [int(x) for x in wf.levels.split(",") if x]

        run = WorkflowRun(workflow_id=workflow_id, status="Running", trigger_type=trigger_type)
        session.add(run)
        session.commit()
        session.refresh(run)

        runtime_context: dict[str, Any] = {
            "run_id": run.id,
            "session_id": f"workflow-{run.id}",
            "workflow": {
                "id": wf.id,
                "name": wf.name,
                "require_approval": wf.require_approval,
                "webhook_url": wf.webhook_url,
            },
            "levels": levels,
        }

        def node1_fetch(ctx: dict[str, Any]) -> dict[str, Any]:
            payloads = registry.get("event_query").execute(
                ctx["session_id"],
                {
                    "severities": levels,
                    "time_text": "今天",
                    "page": 1,
                    "page_size": 50,
                },
                "workflow fetch",
            )
            table = next((p for p in payloads if p["type"] == "table"), None)
            rows = table["data"]["rows"] if table else []
            return {"count": len(rows), "rows": rows}

        def node2_event_detail(ctx: dict[str, Any]) -> dict[str, Any]:
            rows = ctx["nodes"]["fetch_events"]["rows"]
            uuids = [r["uuId"] for r in rows[:10]]
            if not uuids:
                return {"details": []}
            payloads = registry.get("event_detail").execute(ctx["session_id"], {"uuids": uuids}, "workflow detail")
            return {"details": payloads}

        def node2_entity(ctx: dict[str, Any]) -> dict[str, Any]:
            rows = ctx["nodes"]["fetch_events"]["rows"]
            ips = [r.get("hostIp") for r in rows[:10] if r.get("hostIp")]
            if not ips:
                return {"entities": []}
            payloads = registry.get("entity_query").execute(ctx["session_id"], {"ips": ips[:5]}, "workflow entity")
            return {"entities": payloads}

        def node3_summary(ctx: dict[str, Any]) -> dict[str, Any]:
            llm = LLMRouter(session)
            rows = ctx["nodes"]["fetch_events"]["rows"]
            detail = ctx["nodes"].get("event_detail", {})
            entity = ctx["nodes"].get("entity_query", {})
            prompt = (
                "请作为安全运营专家，基于以下证据输出研判结论和处置建议。"
                f"\n事件条数: {len(rows)}"
                f"\n事件样本: {json.dumps(rows[:3], ensure_ascii=False)}"
                f"\n详情: {json.dumps(detail, ensure_ascii=False)[:1200]}"
                f"\n实体情报: {json.dumps(entity, ensure_ascii=False)[:1200]}"
            )
            summary = llm.complete(prompt, system="你是XDR专家，只输出可执行建议。")
            return {"summary": summary}

        nodes = [
            PipelineNode("fetch_events", node1_fetch),
            PipelineNode("event_detail", node2_event_detail, depends_on=["fetch_events"]),
            PipelineNode("entity_query", node2_entity, depends_on=["fetch_events"]),
            PipelineNode("llm_summary", node3_summary, depends_on=["event_detail", "entity_query"]),
        ]

        results = self.engine.run(nodes, runtime_context)
        summary = results["llm_summary"]["summary"]
        event_rows = results["fetch_events"]["rows"]

        run_context = {
            "events": event_rows,
            "summary": summary,
            "session_id": runtime_context["session_id"],
            "workflow": runtime_context["workflow"],
        }

        if wf.require_approval:
            approval_payload_data = approval_payload(
                title="每日高危事件处置审批",
                summary=summary,
                token=f"workflow-run-{run.id}",
                details={"count": len(event_rows), "events": event_rows[:5]},
            )
            approval = ApprovalRequest(
                workflow_run_id=run.id,
                title="每日高危事件处置审批",
                payload_json=json.dumps(approval_payload_data, ensure_ascii=False),
                status="Pending",
            )
            session.add(approval)
            run.status = "Suspended"
            run.context_json = json.dumps(run_context, ensure_ascii=False)
            session.add(run)
            session.commit()
            session.refresh(run)
            return run

        apply_result = self._apply_decision_actions(session, run_context)
        run.status = "Finished"
        run.result_json = json.dumps(apply_result, ensure_ascii=False)
        run.finished_at = datetime.utcnow()
        session.add(run)
        session.commit()
        session.refresh(run)
        return run

    def list_approvals(self, session: Session) -> list[ApprovalRequest]:
        return session.exec(select(ApprovalRequest).order_by(ApprovalRequest.id.desc())).all()

    def _apply_decision_actions(self, session: Session, run_context: dict[str, Any]) -> dict[str, Any]:
        _, registry = self._load_runtime(session)
        events = run_context.get("events", [])
        uuids = [e["uuId"] for e in events[:5] if e.get("uuId")]

        payloads = []
        if uuids:
            payloads.extend(
                registry.get("event_action").execute(
                    run_context.get("session_id", "workflow"),
                    {"uuids": uuids, "deal_status": 10, "deal_comment": "Workflow自动推进", "confirm": True},
                    "workflow action",
                )
            )

        # 演示性封禁：取第一条事件IP进行临时封禁
        first_ip = next((e.get("hostIp") for e in events if e.get("hostIp")), None)
        if first_ip:
            payloads.extend(
                registry.get("block_action").execute(
                    run_context.get("session_id", "workflow"),
                    {
                        "block_type": "SRC_IP",
                        "views": [first_ip],
                        "time_type": "temporary",
                        "time_value": 2,
                        "time_unit": "h",
                        "confirm": True,
                    },
                    "workflow block",
                )
            )

        webhook = run_context.get("workflow", {}).get("webhook_url")
        if webhook:
            msg = "\n".join([p["data"].get("text", "") for p in payloads if p["type"] == "text"])
            try:
                httpx.post(webhook, json={"msgtype": "text", "text": {"content": f"Flux闭环执行完成\n{msg}"}}, timeout=8)
            except Exception:
                pass

        return {"payloads": payloads}

    def decide_approval(
        self,
        session: Session,
        approval_id: int,
        *,
        decision: str,
        reviewer: str,
        comment: str | None,
    ) -> dict[str, Any]:
        approval = session.get(ApprovalRequest, approval_id)
        if not approval:
            raise ValueError("approval not found")
        run = session.get(WorkflowRun, approval.workflow_run_id)
        if not run:
            raise ValueError("workflow run not found")

        approval.status = "Approved" if decision == "approve" else "Rejected"
        approval.decision = decision
        approval.reviewer = reviewer
        approval.updated_at = datetime.utcnow()
        session.add(approval)

        if decision == "reject":
            run.status = "Rejected"
            run.finished_at = datetime.utcnow()
            run.result_json = json.dumps({"message": comment or "审批拒绝"}, ensure_ascii=False)
            session.add(run)
            session.commit()
            return {"status": "Rejected", "message": "审批已拒绝，流程结束"}

        run_context = json.loads(run.context_json or "{}")
        result = self._apply_decision_actions(session, run_context)
        run.status = "Finished"
        run.finished_at = datetime.utcnow()
        run.result_json = json.dumps(result, ensure_ascii=False)
        session.add(run)
        session.commit()
        return {"status": "Finished", "result": result}


workflow_service = WorkflowService()


def run_workflow_job(workflow_id: int) -> None:
    with session_scope() as session:
        workflow_service.run_workflow(session, workflow_id=workflow_id, trigger_type="cron")
