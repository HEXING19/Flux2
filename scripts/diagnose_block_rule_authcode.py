#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.signature import Signature  # noqa: E402


def normalize_text(value: object) -> str:
    return str(value or "").strip()


def is_linkable(device: dict[str, object]) -> bool:
    remark = normalize_text(device.get("remark"))
    status = normalize_text(device.get("deviceStatus")).lower()
    if remark:
        if "不可联动" in remark:
            return False
        if "可联动" in remark:
            return True
    return status == "online"


def signed_post_raw(base_url: str, path: str, body_text: str, auth_code: str, verify_ssl: bool) -> dict[str, object]:
    url = f"{base_url.rstrip('/')}{path}"
    req = requests.Request(
        "POST",
        url,
        headers={"content-type": "application/json"},
        data=body_text,
    )
    Signature(auth_code=auth_code).sign(req)
    req.headers["x-flux-request-id"] = uuid.uuid4().hex[:16]

    session = requests.Session()
    session.verify = verify_ssl
    response = session.send(session.prepare_request(req), timeout=20)
    try:
        body = response.json()
    except Exception:
        body = {"raw": response.text[:2000]}
    return {
        "status_code": response.status_code,
        "body": body,
    }


def fetch_linkable_device(base_url: str, auth_code: str, verify_ssl: bool) -> dict[str, object]:
    payload = json.dumps({"type": ["AF"]}, ensure_ascii=False)
    result = signed_post_raw(base_url, "/api/xdr/v1/device/blockdevice/list", payload, auth_code, verify_ssl)
    body = result.get("body")
    if not isinstance(body, dict):
        raise RuntimeError(f"设备查询返回非 JSON: {result}")
    data = body.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(f"设备查询缺少 data: {body}")
    items = data.get("item")
    if not isinstance(items, list):
        raise RuntimeError(f"设备查询缺少 item 列表: {body}")
    for item in items:
        if isinstance(item, dict) and is_linkable(item):
            return item
    raise RuntimeError(f"未找到可联动 AF 设备: {body}")


def dumps_payload(payload: dict[str, object], *, ensure_ascii: bool, compact: bool) -> str:
    kwargs = {"ensure_ascii": ensure_ascii}
    if compact:
        kwargs["separators"] = (",", ":")
    return json.dumps(payload, **kwargs)


def build_probe_payload(device: dict[str, object], *, reason: str, dev_name: str) -> dict[str, object]:
    return {
        "name": f"Flux_auth_probe_{uuid.uuid4().hex[:8]}",
        "reason": reason,
        "timeType": "temporary",
        "timeValue": 0,
        "timeUnit": "h",
        "blockIpRule": {
            "type": "SRC_IP",
            "mode": "in",
            "view": ["198.51.100.10"],
        },
        "devices": [
            {
                "devId": device.get("deviceId"),
                "devName": dev_name,
                "devType": device.get("deviceType"),
                "devVersion": device.get("deviceVersion"),
            }
        ],
    }


def summarize_response(result: dict[str, object]) -> dict[str, object]:
    body = result.get("body")
    message = ""
    code = None
    if isinstance(body, dict):
        message = normalize_text(body.get("message") or body.get("msg") or body.get("error"))
        code = body.get("code")
    return {
        "status_code": result.get("status_code"),
        "code": code,
        "message": message,
        "body": body,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose auth-code compatibility for block rule create API.")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--auth-code", required=True)
    parser.add_argument("--verify-ssl", action="store_true")
    args = parser.parse_args()

    device = fetch_linkable_device(args.base_url, args.auth_code, args.verify_ssl)
    actual_name = normalize_text(device.get("deviceName"))
    ascii_name = f"AF_{normalize_text(device.get('deviceId'))}"[:8] or "AF_TEST"

    variants: list[tuple[str, dict[str, object], bool, bool]] = [
        (
            "current_utf8_pretty",
            build_probe_payload(device, reason="由安全早报一键处置触发（攻击源封禁）", dev_name=actual_name),
            False,
            False,
        ),
        (
            "current_ascii_escaped_pretty",
            build_probe_payload(device, reason="由安全早报一键处置触发（攻击源封禁）", dev_name=actual_name),
            True,
            False,
        ),
        (
            "current_ascii_escaped_compact",
            build_probe_payload(device, reason="由安全早报一键处置触发（攻击源封禁）", dev_name=actual_name),
            True,
            True,
        ),
        (
            "ascii_reason_ascii_device_utf8",
            build_probe_payload(device, reason="flux-auth-probe", dev_name=ascii_name),
            False,
            False,
        ),
        (
            "ascii_reason_ascii_device_compact",
            build_probe_payload(device, reason="flux-auth-probe", dev_name=ascii_name),
            True,
            True,
        ),
    ]

    results = []
    for name, payload, ensure_ascii, compact in variants:
        body_text = dumps_payload(payload, ensure_ascii=ensure_ascii, compact=compact)
        response = signed_post_raw(
            args.base_url,
            "/api/xdr/v1/responses/blockiprule/network",
            body_text,
            args.auth_code,
            args.verify_ssl,
        )
        results.append(
            {
                "variant": name,
                "serialization": {
                    "ensure_ascii": ensure_ascii,
                    "compact": compact,
                },
                "request_body": body_text,
                "response": summarize_response(response),
            }
        )

    output = {
        "device": {
            "deviceId": normalize_text(device.get("deviceId")),
            "deviceName": actual_name,
            "deviceStatus": normalize_text(device.get("deviceStatus")),
            "remark": normalize_text(device.get("remark")),
        },
        "note": "所有探针都使用 timeValue=0，目的是故意触发参数校验，避免真实创建封禁规则。若仍返回401，则说明请求在鉴权层即被拒绝。",
        "results": results,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
