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


def request_block_devices(base_url: str, auth_code: str, verify_ssl: bool) -> dict[str, object]:
    url = f"{base_url.rstrip('/')}/api/xdr/v1/device/blockdevice/list"
    payload = {"type": ["AF"]}

    req = requests.Request(
        "POST",
        url,
        headers={"content-type": "application/json"},
        data=json.dumps(payload, ensure_ascii=False),
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
        "headers": dict(response.headers),
        "body": body,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe AF block-device list API.")
    parser.add_argument("--base-url", required=True, help="XDR base URL, for example https://10.5.41.194")
    parser.add_argument("--auth-code", required=True, help="Link auth code")
    parser.add_argument("--verify-ssl", action="store_true", help="Enable SSL certificate verification")
    args = parser.parse_args()

    result = request_block_devices(args.base_url, args.auth_code, args.verify_ssl)
    body = result.get("body")
    items = []
    if isinstance(body, dict):
        data = body.get("data")
        if isinstance(data, dict):
            raw_items = data.get("item")
            if isinstance(raw_items, list):
                items = [item for item in raw_items if isinstance(item, dict)]

    linkable = [item for item in items if is_linkable(item)]
    output = {
        "request": {
            "base_url": args.base_url,
            "path": "/api/xdr/v1/device/blockdevice/list",
            "payload": {"type": ["AF"]},
            "verify_ssl": args.verify_ssl,
        },
        "response": {
            "status_code": result.get("status_code"),
            "body": body,
        },
        "summary": {
            "total_items": len(items),
            "linkable_count": len(linkable),
            "linkable_devices": [
                {
                    "deviceId": normalize_text(item.get("deviceId")),
                    "deviceName": normalize_text(item.get("deviceName")),
                    "deviceStatus": normalize_text(item.get("deviceStatus")),
                    "deviceType": normalize_text(item.get("deviceType")),
                    "deviceVersion": normalize_text(item.get("deviceVersion")),
                    "remark": normalize_text(item.get("remark")),
                }
                for item in linkable
            ],
        },
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
