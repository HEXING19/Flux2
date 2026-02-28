from __future__ import annotations

import json
import time
import uuid
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
        method_upper = method.upper().strip()
        request_id = uuid.uuid4().hex[:16]
        sign_headers = {"content-type": "application/json"}

        for attempt in range(1, max_retries + 1):
            try:
                req_kwargs: dict[str, Any] = {"headers": dict(sign_headers), "params": params}
                if json_body is not None:
                    req_kwargs["data"] = json.dumps(json_body, ensure_ascii=False)
                elif method_upper in {"POST", "PUT", "PATCH"}:
                    req_kwargs["data"] = "{}"

                req = requests.Request(method_upper, url, **req_kwargs)
                if self.signature:
                    self.signature.sign(req)
                # Add tracing header after signature to avoid signature mismatch in strict gateways.
                req.headers["x-flux-request-id"] = request_id
                response = self.session.send(req.prepare(), timeout=timeout)

                body: dict[str, Any] | None = None
                try:
                    parsed = response.json()
                    if isinstance(parsed, dict):
                        body = parsed
                except Exception:
                    body = None

                if response.status_code >= 500 and attempt < max_retries:
                    time.sleep(min(1.5 * attempt, 4.0))
                    continue

                if response.status_code >= 400:
                    message = ""
                    if body and body.get("message"):
                        message = str(body.get("message"))
                    elif response.text:
                        message = response.text[:400]
                    else:
                        message = f"HTTP {response.status_code}"

                    if response.status_code in {401, 403}:
                        message = f"{message}。认证失败或权限不足，请重新登录并确认账号已开通该接口权限。"

                    return {
                        "code": "Failed",
                        "message": f"请求失败({response.status_code}): {message} (request_id={request_id})",
                        "data": body.get("data", {}) if isinstance(body, dict) else {},
                        "requestId": request_id,
                    }

                if body is not None:
                    body.setdefault("requestId", request_id)
                    return body

                return {
                    "code": "Failed",
                    "message": f"请求成功但响应不是JSON (request_id={request_id})",
                    "data": {"raw": response.text[:1000]},
                    "requestId": request_id,
                }
            except Exception as exc:
                if attempt == max_retries:
                    return {
                        "code": "Failed",
                        "message": f"请求失败: {exc} (request_id={request_id})",
                        "data": {},
                    }
                time.sleep(min(1.5 * attempt, 4.0))

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
