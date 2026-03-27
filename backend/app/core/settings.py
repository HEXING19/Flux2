from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_db_path() -> str:
    project_root = Path(__file__).resolve().parents[3]
    preferred = project_root / "data" / "flux.db"
    legacy = project_root / "flux.db"
    if preferred.exists():
        return str(preferred)
    if legacy.exists():
        return str(legacy)
    return str(preferred)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Flux XDR"
    app_env: Literal["dev", "test", "prod"] = "dev"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    app_reload: bool = False

    db_path: str = Field(default_factory=_default_db_path)

    default_llm_provider: str = "openai"
    default_llm_model: str = "gpt-4o-mini"

    llm_timeout_seconds: int = 30
    llm_max_retries: int = 3

    xdr_base_url: str | None = None
    xdr_verify_ssl: bool = False

    threatbook_api_key: str | None = None
    webhook_url: str | None = None

    static_dir: str = str(Path(__file__).resolve().parents[3] / "frontend")

    @property
    def sqlite_url(self) -> str:
        return f"sqlite:///{self.db_path}"


settings = Settings()
