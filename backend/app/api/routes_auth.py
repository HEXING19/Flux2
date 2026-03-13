from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from sqlmodel import select

from app.core.db import get_session
from app.core.requester import APIRequester
from app.core.signature import Signature
from app.models.db_models import XDRCredential
from app.models.schemas import LoginRequest, LoginResponse
from app.services.config_service import ConfigService


router = APIRouter(prefix="/api/auth", tags=["auth"])


def _validate_payload(payload: LoginRequest) -> None:
    try:
        if payload.auth_code:
            Signature(auth_code=payload.auth_code)
        else:
            Signature(ak=payload.access_key, sk=payload.secret_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"联动码/AKSK格式非法: {exc}") from exc


def _probe_connectivity(payload: LoginRequest) -> dict:
    requester = APIRequester(
        base_url=payload.base_url,
        auth_code=payload.auth_code,
        access_key=payload.access_key,
        secret_key=payload.secret_key,
        verify_ssl=payload.verify_ssl,
    )
    test_resp = requester.request(
        "POST",
        "/api/xdr/v1/incidents/list",
        json_body={"page": 1, "pageSize": 5},
    )
    return test_resp


@router.post("/probe")
def probe(payload: LoginRequest):
    _validate_payload(payload)
    test_resp = _probe_connectivity(payload)
    if test_resp.get("code") != "Success":
        raise HTTPException(
            status_code=400,
            detail=f"连通性探测失败: {test_resp.get('message', '接口不可达或凭证无效')}",
        )
    return {"success": True, "message": "连通性探测成功，认证信息可用。"}


@router.get("/status")
def auth_status(session: Session = Depends(get_session)):
    from app.core.requester import get_requester_from_credential

    credential = session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
    if not credential:
        return {"authenticated": False}

    # Real-time probe to determine if the configured server is reachable right now
    requester = get_requester_from_credential(credential)
    test_resp = requester.request(
        "POST",
        "/api/xdr/v1/incidents/list",
        json_body={"page": 1, "pageSize": 1},
        timeout=60,
        max_retries=1,
    )
    is_connected = test_resp.get("code") == "Success"

    return {
        "authenticated": True,
        "connected": is_connected,
        "base_url": credential.base_url,
        "verify_ssl": credential.verify_ssl,
    }


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, session: Session = Depends(get_session)) -> LoginResponse:
    _validate_payload(payload)
    test_resp = _probe_connectivity(payload)
    if test_resp.get("code") != "Success":
        raise HTTPException(status_code=400, detail=f"登录失败: {test_resp.get('message', '连通性异常')}")

    service = ConfigService(session)
    service.save_xdr_credential(
        {
            "base_url": payload.base_url,
            "auth_code": payload.auth_code,
            "access_key": payload.access_key,
            "secret_key": payload.secret_key,
            "verify_ssl": payload.verify_ssl,
        }
    )
    return LoginResponse(success=True, message="登录成功并已保存凭证")


@router.post("/logout", response_model=LoginResponse)
def logout(session: Session = Depends(get_session)) -> LoginResponse:
    service = ConfigService(session)
    service.clear_xdr_credentials()
    return LoginResponse(success=True, message="已退出登录并清除已保存凭证")
