from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any

from .time_parser import parse_cn_number


@dataclass
class SessionContext:
    params_memory: dict[str, Any] = field(default_factory=dict)
    index_memory: dict[str, list[str]] = field(default_factory=dict)
    index_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    pending_action: dict[str, Any] | None = None
    pending_form: dict[str, Any] | None = None


class SkillContextManager:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionContext] = {}
        self._lock = threading.Lock()

    def _get_or_create(self, session_id: str) -> SessionContext:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionContext()
            return self._sessions[session_id]

    def update_params(self, session_id: str, params: dict[str, Any]) -> None:
        context = self._get_or_create(session_id)
        for key, value in params.items():
            if value is not None and value != "":
                context.params_memory[key] = value

    def inherit_params(self, session_id: str, current: dict[str, Any], required_fields: list[str]) -> dict[str, Any]:
        context = self._get_or_create(session_id)
        merged = dict(current)
        for field in required_fields:
            if merged.get(field) is None and field in context.params_memory:
                merged[field] = context.params_memory[field]
        return merged

    def store_index_mapping(
        self,
        session_id: str,
        namespace: str,
        ids: list[str],
        *,
        meta: dict[str, Any] | None = None,
    ) -> None:
        context = self._get_or_create(session_id)
        context.index_memory[namespace] = list(ids)
        context.index_meta[namespace] = meta or {}

    def get_index_mapping(self, session_id: str, namespace: str) -> list[str]:
        return self._get_or_create(session_id).index_memory.get(namespace, [])

    def get_param(self, session_id: str, field_name: str) -> Any:
        return self._get_or_create(session_id).params_memory.get(field_name)

    def save_pending_action(self, session_id: str, action: dict[str, Any]) -> None:
        self._get_or_create(session_id).pending_action = action

    def pop_pending_action(self, session_id: str) -> dict[str, Any] | None:
        context = self._get_or_create(session_id)
        data = context.pending_action
        context.pending_action = None
        return data

    def peek_pending_action(self, session_id: str) -> dict[str, Any] | None:
        return self._get_or_create(session_id).pending_action

    def save_pending_form(self, session_id: str, form: dict[str, Any]) -> None:
        self._get_or_create(session_id).pending_form = form

    def pop_pending_form(self, session_id: str) -> dict[str, Any] | None:
        context = self._get_or_create(session_id)
        data = context.pending_form
        context.pending_form = None
        return data

    def peek_pending_form(self, session_id: str) -> dict[str, Any] | None:
        return self._get_or_create(session_id).pending_form

    def resolve_indices(self, session_id: str, namespace: str, utterance: str) -> list[str]:
        ids = self.get_index_mapping(session_id, namespace)
        if not ids:
            return []

        text = utterance.strip()
        if not text:
            return []

        selected_indexes = set()
        all_indexes = set(range(1, len(ids) + 1))

        if any(keyword in text for keyword in ["全部", "所有", "全都"]):
            selected_indexes = set(all_indexes)

        prefix_match = re.search(r"前(\d+|[一二两三四五六七八九十]+)个", text)
        if prefix_match:
            n = parse_cn_number(prefix_match.group(1)) or 0
            selected_indexes.update(range(1, min(len(ids), n) + 1))

        numeric_indexes = re.findall(r"第\s*(\d+)\s*(?:个|条|项)?", text)
        for token in numeric_indexes:
            idx = int(token)
            if 1 <= idx <= len(ids):
                selected_indexes.add(idx)

        cn_indexes = re.findall(r"第\s*([一二两三四五六七八九十]+)\s*(?:个|条|项)?", text)
        for token in cn_indexes:
            parsed = parse_cn_number(token)
            if parsed and 1 <= parsed <= len(ids):
                selected_indexes.add(parsed)

        single_num = re.findall(r"\b(\d+)\b", text)
        if not numeric_indexes and single_num:
            for token in single_num:
                idx = int(token)
                if 1 <= idx <= len(ids):
                    selected_indexes.add(idx)

        excluded_indexes = set()
        for pattern in [r"跳过第\s*(\d+)\s*(?:个|条|项)?", r"除(?:了)?第\s*(\d+)\s*(?:个|条|项)?"]:
            for token in re.findall(pattern, text):
                idx = int(token)
                if 1 <= idx <= len(ids):
                    excluded_indexes.add(idx)

        if "剩下" in text or "其余" in text:
            if excluded_indexes:
                selected_indexes.update(all_indexes - excluded_indexes)
            elif selected_indexes:
                selected_indexes = all_indexes - selected_indexes
            else:
                selected_indexes = all_indexes

        if not selected_indexes and ("那个" in text or "刚刚" in text):
            selected_indexes.add(1)

        selected_indexes = (selected_indexes or all_indexes if "都" in text else selected_indexes)
        selected_indexes = {idx for idx in selected_indexes if idx not in excluded_indexes}

        ordered = sorted(selected_indexes)
        return [ids[i - 1] for i in ordered]


context_manager = SkillContextManager()
