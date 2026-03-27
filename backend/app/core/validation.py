from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


EVENT_UUID_PATTERN = re.compile(r"^incident-[A-Za-z0-9-]{6,}$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$"
)


def clean_text(value: object) -> str:
    return str(value or "").strip()


def clean_optional_text(value: object) -> str | None:
    text = clean_text(value)
    return text or None


def validate_http_url(value: object, *, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} 不能为空。")
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{field_name} 必须是合法的 http/https URL。")
    return text


def validate_ipv4(value: object, *, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} 不能为空。")
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} 必须是合法的 IPv4 地址。") from exc
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ValueError(f"{field_name} 必须是合法的 IPv4 地址。")
    return str(parsed)


def validate_ipv4_list(values: object, *, field_name: str, allow_empty: bool = False) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field_name} 必须是数组。")
    normalized: list[str] = []
    seen: set[str] = set()
    for idx, item in enumerate(values, start=1):
        ip = validate_ipv4(item, field_name=f"{field_name}[{idx}]")
        if ip in seen:
            continue
        seen.add(ip)
        normalized.append(ip)
    if not allow_empty and not normalized:
        raise ValueError(f"{field_name} 不能为空。")
    return normalized


def validate_incident_uuid(value: object, *, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} 不能为空。")
    if not EVENT_UUID_PATTERN.match(text):
        raise ValueError(f"{field_name} 格式不合法。")
    return text


def validate_incident_uuid_list(values: object, *, field_name: str, allow_empty: bool = False) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field_name} 必须是数组。")
    normalized: list[str] = []
    seen: set[str] = set()
    for idx, item in enumerate(values, start=1):
        uid = validate_incident_uuid(item, field_name=f"{field_name}[{idx}]")
        if uid in seen:
            continue
        seen.add(uid)
        normalized.append(uid)
    if not allow_empty and not normalized:
        raise ValueError(f"{field_name} 不能为空。")
    return normalized


def validate_domain(value: object, *, field_name: str) -> str:
    text = clean_text(value).lower().rstrip(".")
    if not text:
        raise ValueError(f"{field_name} 不能为空。")
    if not DOMAIN_PATTERN.match(text):
        raise ValueError(f"{field_name} 必须是合法的域名。")
    return text


def validate_cidr(value: object, *, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} 不能为空。")
    if "/" not in text:
        raise ValueError(f"{field_name} 必须是合法的 CIDR。")
    try:
        parsed = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"{field_name} 必须是合法的 CIDR。") from exc
    return str(parsed)


def validate_cron_expr(value: object, *, field_name: str = "cron_expr") -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} 不能为空。")
    parts = text.split()
    if len(parts) != 5:
        raise ValueError(f"{field_name} 必须是 5 段 cron 表达式。")
    if any(not part.strip() for part in parts):
        raise ValueError(f"{field_name} 不能包含空字段。")
    return " ".join(parts)


def validate_time_range(
    start_ts: int | None,
    end_ts: int | None,
    *,
    start_name: str = "startTimestamp",
    end_name: str = "endTimestamp",
) -> None:
    if start_ts is not None and start_ts < 0:
        raise ValueError(f"{start_name} 不能小于 0。")
    if end_ts is not None and end_ts < 0:
        raise ValueError(f"{end_name} 不能小于 0。")
    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        raise ValueError(f"{start_name} 不能晚于 {end_name}。")


def validate_url_target(value: object, *, field_name: str) -> str:
    text = clean_text(value)
    if not text:
        raise ValueError(f"{field_name} 不能为空。")
    if text.startswith(("http://", "https://")):
        return validate_http_url(text, field_name=field_name)
    host, sep, _rest = text.partition("/")
    if not sep:
        raise ValueError(f"{field_name} 必须是合法的 URL。")
    try:
        validate_ipv4(host, field_name=field_name)
        return text
    except ValueError:
        validate_domain(host, field_name=field_name)
        return text


def infer_block_view_type(value: object) -> str | None:
    text = clean_text(value)
    if not text:
        return None
    try:
        validate_ipv4(text, field_name="view")
        return "ip"
    except ValueError:
        pass
    try:
        validate_domain(text, field_name="view")
        return "domain"
    except ValueError:
        pass
    try:
        validate_url_target(text, field_name="view")
        return "url"
    except ValueError:
        pass
    return None


def validate_block_view(value: object, *, block_type: str, field_name: str) -> str:
    normalized_type = clean_text(block_type).upper()
    if normalized_type in {"SRC_IP", "DST_IP"}:
        return validate_ipv4(value, field_name=field_name)
    if normalized_type == "DNS":
        return validate_domain(value, field_name=field_name)
    if normalized_type == "URL":
        return validate_url_target(value, field_name=field_name)
    raise ValueError(f"{field_name} 的 block_type 非法。")
