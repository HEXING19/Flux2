from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Iterable

from openai import OpenAI
from zhipuai import ZhipuAI


class BaseLLMProvider(ABC):
    def __init__(self, model_name: str, timeout: int = 30, retries: int = 3) -> None:
        self.model_name = model_name
        self.timeout = timeout
        self.retries = retries

    @abstractmethod
    def generate(self, prompt: str, system: str | None = None) -> str:
        raise NotImplementedError

    def stream(self, prompt: str, system: str | None = None) -> Iterable[str]:
        text = self.generate(prompt, system=system)
        for ch in text:
            yield ch


class OpenAICompatProvider(BaseLLMProvider):
    def __init__(self, api_key: str, model_name: str, base_url: str | None = None, timeout: int = 30, retries: int = 3):
        super().__init__(model_name=model_name, timeout=timeout, retries=retries)
        kwargs = {"api_key": api_key, "timeout": timeout}
        if base_url:
            kwargs["base_url"] = base_url
        self.client = OpenAI(**kwargs)

    def generate(self, prompt: str, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                resp = self.client.chat.completions.create(model=self.model_name, messages=messages)
                return resp.choices[0].message.content or ""
            except Exception as exc:  # pragma: no cover - 网络相关
                last_error = exc
                if attempt < self.retries - 1:
                    time.sleep(1.2 * (attempt + 1))
        raise RuntimeError(f"LLM调用失败: {last_error}")


class ZhipuProvider(BaseLLMProvider):
    def __init__(self, api_key: str, model_name: str, timeout: int = 30, retries: int = 3):
        super().__init__(model_name=model_name, timeout=timeout, retries=retries)
        self.client = ZhipuAI(api_key=api_key)

    def generate(self, prompt: str, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                resp = self.client.chat.completions.create(model=self.model_name, messages=messages)
                return resp.choices[0].message.content or ""
            except Exception as exc:  # pragma: no cover - 网络相关
                last_error = exc
                if attempt < self.retries - 1:
                    time.sleep(1.2 * (attempt + 1))
        raise RuntimeError(f"智谱调用失败: {last_error}")
