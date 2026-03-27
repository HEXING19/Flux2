from __future__ import annotations

from typing import Any


def text_payload(text: str, *, title: str | None = None, dangerous: bool = False) -> dict[str, Any]:
    return {
        "type": "text",
        "data": {
            "title": title,
            "text": text,
            "dangerous": dangerous,
        },
    }


def table_payload(
    *,
    title: str,
    columns: list[dict[str, str]],
    rows: list[dict[str, Any]],
    namespace: str | None = None,
) -> dict[str, Any]:
    return {
        "type": "table",
        "data": {
            "title": title,
            "columns": columns,
            "rows": rows,
            "namespace": namespace,
        },
    }


def echarts_payload(*, title: str, option: dict[str, Any], summary: str) -> dict[str, Any]:
    return {
        "type": "echarts_graph",
        "data": {
            "title": title,
            "option": option,
            "summary": summary,
        },
    }


def approval_payload(*, title: str, summary: str, token: str, details: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "approval_card",
        "data": {
            "title": title,
            "summary": summary,
            "token": token,
            "details": details,
        },
    }


def quick_action_payload(
    *,
    title: str,
    text: str,
    actions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "type": "quick_actions",
        "data": {
            "title": title,
            "text": text,
            "actions": actions,
        },
    }


def form_payload(
    *,
    title: str,
    description: str,
    token: str,
    intent: str,
    fields: list[dict[str, Any]],
    submit_label: str = "提交",
) -> dict[str, Any]:
    return {
        "type": "form_card",
        "data": {
            "title": title,
            "description": description,
            "token": token,
            "intent": intent,
            "fields": fields,
            "submitLabel": submit_label,
        },
    }
