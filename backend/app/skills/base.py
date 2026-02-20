from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, ValidationError

from app.core.context import SkillContextManager
from app.core.exceptions import MissingParameterException, ValidationGuardException
from app.core.requester import APIRequester
from app.core.time_parser import parse_time_range


class SkillInput(BaseModel):
    pass


class BaseSkill(ABC):
    name: str = "base"
    __init_schema__ = SkillInput
    required_fields: list[str] = []
    requires_confirmation: bool = False

    def __init__(self, requester: APIRequester, context_manager: SkillContextManager):
        self.requester = requester
        self.context_manager = context_manager

    def validate_and_prepare(self, session_id: str, params: dict[str, Any]) -> BaseModel:
        merged = self.context_manager.inherit_params(session_id, params, self.required_fields)
        missing = [f for f in self.required_fields if merged.get(f) in (None, "", [], {})]
        if missing:
            fields = "、".join(missing)
            raise MissingParameterException(
                skill_name=self.name,
                missing_fields=missing,
                question=f"为了执行 {self.name}，还缺少参数：{fields}。请补充后我继续执行。",
            )

        if merged.get("time_text") and not (merged.get("startTimestamp") and merged.get("endTimestamp")):
            start_ts, end_ts = parse_time_range(merged["time_text"])
            merged["startTimestamp"] = start_ts
            merged["endTimestamp"] = end_ts

        try:
            model = self.__init_schema__(**merged)
        except ValidationError as exc:
            raise ValidationGuardException(f"{self.name} 参数校验失败: {exc}") from exc

        self.context_manager.update_params(session_id, model.model_dump(exclude_none=True))
        return model

    @abstractmethod
    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        raise NotImplementedError
