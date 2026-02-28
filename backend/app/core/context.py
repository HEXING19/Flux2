from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    def __init__(self, *, enable_persistence: bool = True) -> None:
        self._sessions: dict[str, SessionContext] = {}
        self._lock = threading.Lock()
        self._enable_persistence = enable_persistence

    @staticmethod
    def _safe_json_load(raw: str | None, fallback: Any) -> Any:
        if not raw:
            return fallback
        try:
            return json.loads(raw)
        except Exception:
            return fallback

    def _load_from_db(self, session_id: str) -> SessionContext | None:
        if not self._enable_persistence:
            return None
        try:
            from sqlmodel import select

            from app.core.db import session_scope
            from app.models.db_models import SessionState

            with session_scope() as session:
                row = session.exec(select(SessionState).where(SessionState.session_id == session_id)).first()
                if not row:
                    return None
                return SessionContext(
                    params_memory=self._safe_json_load(row.params_json, {}),
                    index_memory=self._safe_json_load(row.index_json, {}),
                    index_meta=self._safe_json_load(row.index_meta_json, {}),
                    pending_action=self._safe_json_load(row.pending_action_json, None),
                    pending_form=self._safe_json_load(row.pending_form_json, None),
                )
        except Exception:
            return None

    def _persist(self, session_id: str, context: SessionContext) -> None:
        if not self._enable_persistence:
            return
        try:
            from sqlmodel import select

            from app.core.db import session_scope
            from app.models.db_models import SessionState

            with session_scope() as session:
                row = session.exec(select(SessionState).where(SessionState.session_id == session_id)).first()
                if row is None:
                    row = SessionState(session_id=session_id)

                row.params_json = json.dumps(context.params_memory, ensure_ascii=False)
                row.index_json = json.dumps(context.index_memory, ensure_ascii=False)
                row.index_meta_json = json.dumps(context.index_meta, ensure_ascii=False)
                row.pending_action_json = (
                    json.dumps(context.pending_action, ensure_ascii=False) if context.pending_action is not None else None
                )
                row.pending_form_json = (
                    json.dumps(context.pending_form, ensure_ascii=False) if context.pending_form is not None else None
                )
                row.updated_at = datetime.now(timezone.utc)
                session.add(row)
        except Exception:
            # Context persistence is best-effort; runtime flow must keep working.
            return

    def _get_or_create(self, session_id: str) -> SessionContext:
        with self._lock:
            existing = self._sessions.get(session_id)
        if existing is not None:
            return existing

        loaded = self._load_from_db(session_id)
        context = loaded or SessionContext()
        with self._lock:
            cached = self._sessions.get(session_id)
            if cached is not None:
                return cached
            self._sessions[session_id] = context
            return context

    def update_params(self, session_id: str, params: dict[str, Any]) -> None:
        context = self._get_or_create(session_id)
        for key, value in params.items():
            if value is not None and value != "":
                context.params_memory[key] = value
        self._persist(session_id, context)

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
        self._persist(session_id, context)

    def get_index_mapping(self, session_id: str, namespace: str) -> list[str]:
        return self._get_or_create(session_id).index_memory.get(namespace, [])

    def get_param(self, session_id: str, field_name: str) -> Any:
        return self._get_or_create(session_id).params_memory.get(field_name)

    def save_pending_action(self, session_id: str, action: dict[str, Any]) -> None:
        context = self._get_or_create(session_id)
        context.pending_action = action
        self._persist(session_id, context)

    def pop_pending_action(self, session_id: str) -> dict[str, Any] | None:
        context = self._get_or_create(session_id)
        data = context.pending_action
        context.pending_action = None
        self._persist(session_id, context)
        return data

    def peek_pending_action(self, session_id: str) -> dict[str, Any] | None:
        return self._get_or_create(session_id).pending_action

    def save_pending_form(self, session_id: str, form: dict[str, Any]) -> None:
        context = self._get_or_create(session_id)
        context.pending_form = form
        self._persist(session_id, context)

    def pop_pending_form(self, session_id: str) -> dict[str, Any] | None:
        context = self._get_or_create(session_id)
        data = context.pending_form
        context.pending_form = None
        self._persist(session_id, context)
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
        numeric_indexes.extend(re.findall(r"(?:序号|编号)\s*(\d+)", text))
        for token in numeric_indexes:
            idx = int(token)
            if 1 <= idx <= len(ids):
                selected_indexes.add(idx)

        cn_indexes = re.findall(r"第\s*([一二两三四五六七八九十]+)\s*(?:个|条|项)?", text)
        cn_indexes.extend(re.findall(r"(?:序号|编号)\s*([一二两三四五六七八九十]+)", text))
        for token in cn_indexes:
            parsed = parse_cn_number(token)
            if parsed and 1 <= parsed <= len(ids):
                selected_indexes.add(parsed)

        # Support direct ID mention like "incident-xxxx" when index mapping exists.
        for idx, entity_id in enumerate(ids, start=1):
            if isinstance(entity_id, str) and entity_id and entity_id in text:
                selected_indexes.add(idx)

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
