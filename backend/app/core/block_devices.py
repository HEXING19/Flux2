from __future__ import annotations

from typing import Any


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_text(value).lower()


def is_af_device(device: dict[str, Any]) -> bool:
    device_type = _normalize_text(device.get("deviceType")).upper()
    return device_type in {"", "AF"}


def is_linkable_af_device(device: dict[str, Any]) -> bool:
    if not is_af_device(device):
        return False

    remark = _normalize_text(device.get("remark"))
    status = _normalize_lower(device.get("deviceStatus"))

    if remark:
        if "不可联动" in remark:
            return False
        if "可联动" in remark:
            return True
    return status == "online"


def build_device_option(device: dict[str, Any]) -> dict[str, str]:
    return {
        "device_id": _normalize_text(device.get("deviceId")),
        "device_name": _normalize_text(device.get("deviceName")) or "-",
        "device_type": _normalize_text(device.get("deviceType")) or "-",
        "device_version": _normalize_text(device.get("deviceVersion")) or "-",
        "device_ip": _normalize_text(device.get("deviceIp")) or "-",
        "remark": _normalize_text(device.get("remark")) or "-",
    }


def fetch_linkable_af_devices(requester: Any) -> dict[str, Any]:
    resp = requester.request("POST", "/api/xdr/v1/device/blockdevice/list", json_body={"type": ["AF"]})
    if resp.get("code") != "Success":
        message = _normalize_text(resp.get("message")) or "查询封禁设备列表失败。"
        return {
            "ok": False,
            "state": "query_error",
            "message": f"查询 AF 联动设备失败：{message}",
            "devices": [],
            "device_options": [],
            "raw_response": resp,
        }

    raw_items = resp.get("data", {}).get("item", [])
    if not isinstance(raw_items, list):
        raw_items = []
    af_devices = [item for item in raw_items if isinstance(item, dict) and is_af_device(item)]
    if not af_devices:
        return {
            "ok": True,
            "state": "no_device",
            "message": "当前未查询到 AF 设备，请先在平台确认设备接入状态。",
            "devices": [],
            "device_options": [],
            "raw_response": resp,
        }

    linkable_devices = [device for device in af_devices if is_linkable_af_device(device)]
    device_options = [build_device_option(device) for device in linkable_devices if _normalize_text(device.get("deviceId"))]
    if not device_options:
        return {
            "ok": True,
            "state": "no_linkable_device",
            "message": "已查询到 AF 设备，但当前均不可联动，请先在平台确认设备在线状态与联动能力。",
            "devices": [],
            "device_options": [],
            "raw_response": resp,
        }

    count = len(device_options)
    if count == 1:
        success_message = f"已找到可联动 AF 设备：{device_options[0]['device_name']}，可直接联动。"
    else:
        success_message = f"已找到 {count} 台可联动 AF 设备，可直接按设备名称选择联动。"
    return {
        "ok": True,
        "state": "ready",
        "message": success_message,
        "devices": linkable_devices,
        "device_options": device_options,
        "default_device_id": device_options[0]["device_id"],
        "raw_response": resp,
    }
