from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.core.db import get_session
from app.core.settings import settings
from app.llm.providers import OpenAICompatProvider, ZhipuProvider
from app.models.schemas import ProviderConfigIn, ProviderConnectivityRequest
from app.services.config_service import ConfigService


router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("/providers")
def list_providers(session: Session = Depends(get_session)):
    service = ConfigService(session)
    rows = service.list_providers()
    return [
        {
            "id": r.id,
            "provider": r.provider,
            "api_key": r.api_key,
            "base_url": r.base_url,
            "model_name": r.model_name,
            "enabled": r.enabled,
            "updated_at": r.updated_at,
        }
        for r in rows
    ]


@router.post("/providers")
def upsert_provider(payload: ProviderConfigIn, session: Session = Depends(get_session)):
    service = ConfigService(session)
    row = service.upsert_provider(payload.model_dump())
    return {
        "id": row.id,
        "provider": row.provider,
        "enabled": row.enabled,
        "model_name": row.model_name,
        "base_url": row.base_url,
    }


@router.post("/providers/test")
def test_provider(payload: ProviderConnectivityRequest):
    provider = payload.provider
    model = payload.model_name or settings.default_llm_model

    if provider == "zhipu":
        client = ZhipuProvider(api_key=payload.api_key or "", model_name=model)
    elif provider == "deepseek":
        client = OpenAICompatProvider(
            api_key=payload.api_key or "",
            model_name=model,
            base_url=payload.base_url or "https://api.deepseek.com",
        )
    else:
        client = OpenAICompatProvider(
            api_key=payload.api_key or "",
            model_name=model,
            base_url=payload.base_url,
        )

    try:
        result = client.generate("请回复:OK", system="你是连通性测试助手")
        return {"success": True, "message": "连通成功", "sample": result[:120]}
    except Exception as exc:
        return {"success": False, "message": f"连通失败: {exc}"}
