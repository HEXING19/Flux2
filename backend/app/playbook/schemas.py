from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class PlaybookTemplateParam(BaseModel):
    key: str
    label: str
    description: Optional[str] = None
    required: bool = False
    default: Any = None


class PlaybookTemplateMeta(BaseModel):
    id: str
    name: str
    description: str
    button_label: str
    default_params: dict[str, Any] = Field(default_factory=dict)
    params: list[PlaybookTemplateParam] = Field(default_factory=list)


class PlaybookRunRequest(BaseModel):
    template_id: Literal["routine_check", "alert_triage", "threat_hunting"]
    params: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = Field(default=None, min_length=1)
