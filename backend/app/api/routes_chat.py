from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Optional

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from sqlmodel import Session

from app.core.db import get_session
from app.models.schemas import ChatRequest
from app.services.chat_service import ChatService


router = APIRouter(prefix="/api/chat", tags=["chat"])


@router.post("")
def chat(payload: ChatRequest, session: Session = Depends(get_session)):
    service = ChatService(session)
    data = service.handle(payload.session_id, payload.message, active_playbook_run_id=payload.active_playbook_run_id)
    return JSONResponse({"session_id": payload.session_id, "payloads": data})


def _event_stream(service: ChatService, session_id: str, message: str, active_playbook_run_id: Optional[int] = None) -> Iterator[str]:
    payloads = service.handle(session_id, message, active_playbook_run_id=active_playbook_run_id)
    for payload in payloads:
        if payload.get("type") == "text":
            text = payload.get("data", {}).get("text", "")
            yield f"data: {json.dumps({'type': 'text_start', 'payload': payload}, ensure_ascii=False)}\n\n"
            buffer = ""
            for ch in text:
                buffer += ch
                yield f"data: {json.dumps({'type': 'text_delta', 'delta': ch}, ensure_ascii=False)}\n\n"
                time.sleep(0.01)
            yield f"data: {json.dumps({'type': 'text_end', 'text': buffer}, ensure_ascii=False)}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'payload', 'payload': payload}, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"


@router.post("/stream")
def chat_stream(payload: ChatRequest, session: Session = Depends(get_session)):
    service = ChatService(session)
    return StreamingResponse(
        _event_stream(service, payload.session_id, payload.message, active_playbook_run_id=payload.active_playbook_run_id),
        media_type="text/event-stream",
    )
