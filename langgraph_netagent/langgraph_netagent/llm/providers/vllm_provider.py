"""vLLM provider with server-side guided decoding."""

from __future__ import annotations
import logging
from typing import Any, List, Optional, Type, TypeVar
import httpx
from pydantic import BaseModel
from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage, LLMConfig
from langgraph_netagent.llm.parser import build_reflection_prompt, parse_and_validate

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class VLLMProvider(BaseLLMProvider):
    """vLLM provider utilizing guided_json schema masking for 100% token-level syntax compliance."""

    def __init__(self, config: Optional[LLMConfig] = None):
        cfg = config or LLMConfig(
            provider_type="vllm",
            model_name="Qwen/Qwen2.5-Coder-32B-Instruct",
            base_url="http://localhost:8000/v1",
        )
        super().__init__(cfg)
        self.base_url = cfg.base_url or "http://localhost:8000/v1"
        self.api_key = cfg.api_key or "EMPTY"
        self._client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key and self.api_key != "EMPTY":
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

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

    def _build_payload(self, messages: List[ChatMessage], **kwargs: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.config.model_name,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": kwargs.get("temperature", self.config.temperature),
        }
        if "max_tokens" in kwargs:
            payload["max_tokens"] = kwargs["max_tokens"]

        # Inject guided decoding if response_schema is passed
        response_schema = kwargs.get("response_schema")
        if response_schema is not None and issubclass(response_schema, BaseModel):
            payload["extra_body"] = {"guided_json": response_schema.model_json_schema()}

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
            raw_output = self.chat(history, response_schema=response_schema, **kwargs)
            instance, err = parse_and_validate(raw_output, response_schema)
            if instance is not None:
                return instance

            if attempt == retries:
                raise ValueError(
                    f"VLLMProvider: failed validation for {response_schema.__name__} after {retries} retries. Last error: {err}"
                )

            logger.warning("VLLMProvider: guided output failed validation on attempt %d/%d: %s. Initiating retry.", attempt + 1, retries, err)
            history.append(ChatMessage(role="assistant", content=raw_output))
            reflection = build_reflection_prompt(raw_output, err or "Validation failed", response_schema)
            history.append(ChatMessage(role="user", content=reflection))

        raise RuntimeError("Unreachable loop state in VLLMProvider")

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
            raw_output = await self.achat(history, response_schema=response_schema, **kwargs)
            instance, err = parse_and_validate(raw_output, response_schema)
            if instance is not None:
                return instance

            if attempt == retries:
                raise ValueError(
                    f"VLLMProvider: failed validation for {response_schema.__name__} after {retries} retries. Last error: {err}"
                )

            logger.warning("VLLMProvider: async guided output failed validation on attempt %d/%d: %s. Initiating retry.", attempt + 1, retries, err)
            history.append(ChatMessage(role="assistant", content=raw_output))
            reflection = build_reflection_prompt(raw_output, err or "Validation failed", response_schema)
            history.append(ChatMessage(role="user", content=reflection))

        raise RuntimeError("Unreachable loop state in VLLMProvider")
