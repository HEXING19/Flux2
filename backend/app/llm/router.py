from __future__ import annotations

from sqlmodel import Session, select

from app.core.settings import settings
from app.models.db_models import ProviderConfig

from .providers import OpenAICompatProvider, ZhipuProvider


class LLMRouter:
    def __init__(self, session: Session):
        self.session = session

    def _load_provider(self):
        rows = self.session.exec(select(ProviderConfig).where(ProviderConfig.enabled == True)).all()  # noqa: E712
        rows = [row for row in rows if row.provider in {"openai", "zhipu", "deepseek", "custom"}]
        preferred = None
        for row in rows:
            if row.provider == settings.default_llm_provider:
                preferred = row
                break
        if preferred is None and rows:
            preferred = rows[0]

        if preferred is None:
            raise RuntimeError("未配置可用的大模型供应商，请先在系统设置中保存并启用供应商。")

        provider = preferred.provider
        model_name = preferred.model_name or settings.default_llm_model

        if provider == "zhipu":
            if not preferred.api_key:
                raise RuntimeError("智谱供应商缺少 API Key。")
            return ZhipuProvider(
                api_key=preferred.api_key,
                model_name=model_name,
                timeout=settings.llm_timeout_seconds,
                retries=settings.llm_max_retries,
            )
        if provider == "deepseek":
            if not preferred.api_key:
                raise RuntimeError("DeepSeek 供应商缺少 API Key。")
            return OpenAICompatProvider(
                api_key=preferred.api_key,
                model_name=model_name,
                base_url=preferred.base_url or "https://api.deepseek.com",
                timeout=settings.llm_timeout_seconds,
                retries=settings.llm_max_retries,
            )
        if provider in {"openai", "custom"}:
            if not preferred.api_key:
                raise RuntimeError(f"{provider} 供应商缺少 API Key。")
            return OpenAICompatProvider(
                api_key=preferred.api_key,
                model_name=model_name,
                base_url=preferred.base_url,
                timeout=settings.llm_timeout_seconds,
                retries=settings.llm_max_retries,
            )

        raise RuntimeError(f"不支持的供应商类型: {provider}")

    def complete(self, prompt: str, system: str | None = None) -> str:
        provider = self._load_provider()
        return provider.generate(prompt=prompt, system=system)

    def stream(self, prompt: str, system: str | None = None):
        provider = self._load_provider()
        return provider.stream(prompt=prompt, system=system)
