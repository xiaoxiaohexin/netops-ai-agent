"""OpenAI-compatible client for Qwen models (DashScope / OpenAI proxy)."""

from __future__ import annotations
import logging
from typing import Any, List, Optional, Type, TypeVar
import httpx
from pydantic import BaseModel
from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage, LLMConfig
from langgraph_netagent.llm.parser import build_reflection_prompt, parse_and_validate

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class QwenOpenAIProvider(BaseLLMProvider):
    """Provider connecting to DashScope or any OpenAI-compatible API gateway."""

    def __init__(self, config: Optional[LLMConfig] = None):
        import os
        if not os.environ.get("OPENAI_API_KEY") and not os.environ.get("DASHSCOPE_API_KEY"):
            try:
                from pathlib import Path
                from dotenv import load_dotenv
                for c in [
                    Path.cwd() / ".env",
                    Path(__file__).resolve().parent.parent.parent.parent / ".env",
                    Path(__file__).resolve().parent.parent.parent / ".env",
                ]:
                    if c.exists():
                        load_dotenv(c)
                        break
            except Exception:
                pass

        env_key = os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        env_base_url = os.environ.get("OPENAI_BASE_URL") or "https://dashscope.aliyuncs.com/compatible-mode/v1"
        env_model = os.environ.get("OPENAI_MODEL") or os.environ.get("QWEN_MODEL") or "qwen2.5-coder-32b-instruct"

        cfg = config or LLMConfig(
            provider_type="openai",
            model_name=env_model,
            base_url=env_base_url,
            api_key=env_key,
        )
        super().__init__(cfg)
        self.base_url = cfg.base_url or env_base_url
        self.api_key = cfg.api_key or env_key or "EMPTY"
        self._client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    @property
    def client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=self._get_headers(),
                timeout=self.config.timeout_seconds,
            )
        return self._client

    @client.setter
    def client(self, val: httpx.Client) -> None:
        self._client = val

    @property
    def async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._get_headers(),
                timeout=self.config.timeout_seconds,
            )
        return self._async_client

    @async_client.setter
    def async_client(self, val: httpx.AsyncClient) -> None:
        self._async_client = val

    def _build_payload(self, messages: List[ChatMessage], json_mode: Optional[bool] = None, **kwargs: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", self.config.temperature),
        }
        effective_json = kwargs.get("json_mode", json_mode if json_mode is not None else True)
        if effective_json:
            payload["response_format"] = {"type": "json_object"}
            # DeepSeek and strict OpenAI endpoints require the word 'json' in prompt when json_object mode is requested
            has_json = any("json" in (m.content or "").lower() for m in messages)
            if not has_json and payload["messages"]:
                last_msg = dict(payload["messages"][-1])
                last_msg["content"] = (last_msg.get("content") or "") + "\n(Format response as json)"
                payload["messages"] = list(payload["messages"][:-1]) + [last_msg]
        if "max_tokens" in kwargs:
            payload["max_tokens"] = kwargs["max_tokens"]
        return payload

    def chat(self, messages: List[ChatMessage], **kwargs: Any) -> str:
        payload = self._build_payload(messages, **kwargs)
        resp = self.client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def achat(self, messages: List[ChatMessage], **kwargs: Any) -> str:
        payload = self._build_payload(messages, **kwargs)
        resp = await self.async_client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def generate_structured(
        self,
        messages: List[ChatMessage],
        response_schema: Type[T],
        max_retries: Optional[int] = None,
        **kwargs: Any
    ) -> T:
        retries = max_retries if max_retries is not None else self.config.max_retries
        history = [ChatMessage(role=m.role, content=m.content) for m in messages]

        for attempt in range(retries + 1):
            raw_output = self.chat(history, json_mode=True, **kwargs)
            instance, err = parse_and_validate(raw_output, response_schema)
            if instance is not None:
                return instance

            if attempt == retries:
                raise ValueError(
                    f"QwenOpenAIProvider: failed validation for {response_schema.__name__} after {retries} retries. Last error: {err}"
                )

            logger.warning("QwenOpenAIProvider: validation failed on attempt %d/%d: %s. Initiating reflection retry.", attempt + 1, retries, err)
            history.append(ChatMessage(role="assistant", content=raw_output))
            reflection = build_reflection_prompt(raw_output, err or "Validation failed", response_schema)
            history.append(ChatMessage(role="user", content=reflection))

        raise RuntimeError("Unreachable loop state in QwenOpenAIProvider")

    async def agenerate_structured(
        self,
        messages: List[ChatMessage],
        response_schema: Type[T],
        max_retries: Optional[int] = None,
        **kwargs: Any
    ) -> T:
        retries = max_retries if max_retries is not None else self.config.max_retries
        history = [ChatMessage(role=m.role, content=m.content) for m in messages]

        for attempt in range(retries + 1):
            raw_output = await self.achat(history, json_mode=True, **kwargs)
            instance, err = parse_and_validate(raw_output, response_schema)
            if instance is not None:
                return instance

            if attempt == retries:
                raise ValueError(
                    f"QwenOpenAIProvider: failed validation for {response_schema.__name__} after {retries} retries. Last error: {err}"
                )

            logger.warning("QwenOpenAIProvider: async validation failed on attempt %d/%d: %s. Initiating reflection retry.", attempt + 1, retries, err)
            history.append(ChatMessage(role="assistant", content=raw_output))
            reflection = build_reflection_prompt(raw_output, err or "Validation failed", response_schema)
            history.append(ChatMessage(role="user", content=reflection))

        raise RuntimeError("Unreachable loop state in QwenOpenAIProvider")
