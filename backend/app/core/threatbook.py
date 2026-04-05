from __future__ import annotations

from sqlmodel import select

from app.core.db import session_scope
from app.core.settings import settings
from app.models.db_models import ThreatIntelConfig


def mask_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def get_threatbook_key_snapshot() -> dict[str, str | bool | None]:
    with session_scope() as session:
        row = session.exec(
            select(ThreatIntelConfig).where(ThreatIntelConfig.provider == "threatbook")
        ).first()
        if row:
            enabled = bool(row.enabled)
            api_key = row.api_key
        else:
            enabled = None
            api_key = None

    if enabled is not None:
        if not enabled:
            return {"api_key": None, "source": "db", "enabled": False}
        if api_key:
            return {"api_key": api_key, "source": "db", "enabled": True}
    if settings.threatbook_api_key:
        return {"api_key": settings.threatbook_api_key, "source": "env", "enabled": True}
    return {"api_key": None, "source": "none", "enabled": False}


def resolve_threatbook_api_key() -> str | None:
    snapshot = get_threatbook_key_snapshot()
    key = snapshot.get("api_key")
    if isinstance(key, str) and key.strip():
        return key.strip()
    return None
