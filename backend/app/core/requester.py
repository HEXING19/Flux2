from __future__ import annotations

import json
from typing import Any

import requests

from .settings import settings
from .signature import Signature


class APIRequester:
    def __init__(
        self,
        *,
        base_url: str | None,
        auth_code: str | None,
        access_key: str | None,
        secret_key: str | None,
        verify_ssl: bool,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.signature = None
        if auth_code or (access_key and secret_key):
            self.signature = Signature(auth_code=auth_code, ak=access_key, sk=secret_key)

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: int = 15,
        max_retries: int = 3,
    ) -> dict[str, Any]:
        if not self.base_url:
            return {"code": "Failed", "message": "缺少XDR基础地址，请先完成登录配置。", "data": {}}

        url = f"{self.base_url}{path}"
        headers = {"content-type": "application/json"}
        req = requests.Request(method.upper(), url, headers=headers, data=json.dumps(json_body or {}), params=params)
        if self.signature:
            self.signature.sign(req)

        for attempt in range(1, max_retries + 1):
            try:
                response = self.session.send(req.prepare(), timeout=timeout)
                response.raise_for_status()
                return response.json()
            except Exception as exc:
                if attempt == max_retries:
                    return {"code": "Failed", "message": f"请求失败: {exc}", "data": {}}

        return {"code": "Failed", "message": "未知请求错误", "data": {}}


requester_singleton: APIRequester | None = None


def get_requester_from_credential(credential: Any | None) -> APIRequester:
    global requester_singleton
    if credential:
        requester_singleton = APIRequester(
            base_url=credential.base_url,
            auth_code=credential.auth_code,
            access_key=credential.access_key,
            secret_key=credential.secret_key,
            verify_ssl=credential.verify_ssl,
        )
    if requester_singleton is None:
        requester_singleton = APIRequester(
            base_url=settings.xdr_base_url,
            auth_code=None,
            access_key=None,
            secret_key=None,
            verify_ssl=settings.xdr_verify_ssl,
        )
    return requester_singleton
