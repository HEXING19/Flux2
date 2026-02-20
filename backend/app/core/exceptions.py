from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class FluxError(Exception):
    pass


@dataclass
class MissingParameterException(FluxError):
    skill_name: str
    missing_fields: list[str]
    question: str


@dataclass
class ConfirmationRequiredException(FluxError):
    skill_name: str
    summary: str
    action_payload: dict[str, Any]


@dataclass
class ValidationGuardException(FluxError):
    message: str
