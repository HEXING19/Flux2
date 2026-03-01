from __future__ import annotations

import ipaddress
import json

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session

from app.core.db import get_session
from app.core.settings import settings
from app.core.threatbook import mask_secret, resolve_threatbook_api_key
from app.llm.providers import OpenAICompatProvider, ZhipuProvider
from app.models.schemas import CoreAssetIn, ProviderConfigIn, ProviderConnectivityRequest, ThreatbookConfigIn, ThreatbookConnectivityRequest
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


@router.get("/threatbook")
def get_threatbook_config(session: Session = Depends(get_session)):
    service = ConfigService(session)
    row = service.get_threatbook_config()
    if row:
        key = row.api_key
        source = "db"
        enabled = row.enabled
    else:
        key = settings.threatbook_api_key
        source = "env" if settings.threatbook_api_key else "none"
        enabled = bool(settings.threatbook_api_key)
    return {
        "enabled": enabled,
        "has_key": bool(key),
        "masked_key": mask_secret(key),
        "updated_at": row.updated_at if row else None,
        "source": source,
    }


@router.post("/threatbook")
def upsert_threatbook_config(payload: ThreatbookConfigIn, session: Session = Depends(get_session)):
    service = ConfigService(session)
    row = service.upsert_threatbook_config(api_key=payload.api_key, enabled=payload.enabled)
    return {
        "enabled": row.enabled,
        "has_key": bool(row.api_key),
        "masked_key": mask_secret(row.api_key),
        "updated_at": row.updated_at,
    }


@router.post("/threatbook/test")
def test_threatbook_connectivity(payload: ThreatbookConnectivityRequest):
    try:
        ipaddress.ip_address(payload.test_ip)
    except ValueError:
        return {"success": False, "message": "测试 IP 格式不正确。"}

    key = (payload.api_key or "").strip() or resolve_threatbook_api_key()
    if not key:
        return {"success": False, "message": "未检测到 ThreatBook API Key。"}

    try:
        with httpx.Client(timeout=8) as client:
            resp = client.get(
                "https://api.threatbook.cn/v3/scene/ip_reputation",
                params={"apikey": key, "resource": payload.test_ip},
            )
            body = resp.json()
            if not isinstance(body, dict):
                return {"success": False, "message": "ThreatBook 返回格式异常。"}
            if body.get("response_code") != 0:
                return {
                    "success": False,
                    "message": f"ThreatBook 返回错误: {body.get('verbose_msg') or body.get('message') or '未知错误'}",
                }
            data = body.get("data", {}).get(payload.test_ip, {})
            sample = {
                "severity": data.get("severity", "unknown"),
                "confidence_level": data.get("confidence_level", 0),
                "judgment": (data.get("judgments") or ["unknown"])[0],
            }
            return {"success": True, "message": "ThreatBook 连通成功。", "sample": sample}
    except Exception as exc:
        return {"success": False, "message": f"ThreatBook 连通失败: {exc}"}


@router.get("/core-assets")
def list_core_assets(session: Session = Depends(get_session)):
    service = ConfigService(session)
    rows = service.list_core_assets()
    result = []
    for row in rows:
        metadata = {}
        if row.metadata_json:
            try:
                metadata = json.loads(row.metadata_json)
            except Exception:
                metadata = {"raw": row.metadata_json}
        result.append(
            {
                "id": row.id,
                "asset_name": row.asset_name,
                "asset_ip": row.asset_ip,
                "biz_owner": row.biz_owner,
                "metadata": metadata,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
        )
    return result


@router.post("/core-assets")
def create_core_asset(payload: CoreAssetIn, session: Session = Depends(get_session)):
    asset_name = payload.asset_name.strip()
    asset_ip = payload.asset_ip.strip()
    if not asset_name or not asset_ip:
        raise HTTPException(status_code=400, detail="资产名称和IP不能为空。")
    try:
        ipaddress.ip_address(asset_ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="资产IP格式不正确。") from exc

    service = ConfigService(session)
    metadata_raw = (payload.metadata or "").strip()
    metadata_json: str | None = None
    if metadata_raw:
        try:
            parsed = json.loads(metadata_raw)
            metadata_json = json.dumps(parsed, ensure_ascii=False)
        except Exception:
            metadata_json = json.dumps({"note": metadata_raw}, ensure_ascii=False)

    row = service.create_core_asset(
        {
            "asset_name": asset_name,
            "asset_ip": asset_ip,
            "biz_owner": (payload.biz_owner or "").strip() or None,
            "metadata_json": metadata_json,
        }
    )
    return {
        "id": row.id,
        "asset_name": row.asset_name,
        "asset_ip": row.asset_ip,
        "biz_owner": row.biz_owner,
        "metadata": json.loads(row.metadata_json) if row.metadata_json else {},
        "updated_at": row.updated_at,
    }


@router.delete("/core-assets/{asset_id}")
def delete_core_asset(asset_id: int, session: Session = Depends(get_session)):
    service = ConfigService(session)
    deleted = service.delete_core_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="核心资产不存在。")
    return {"success": deleted}
