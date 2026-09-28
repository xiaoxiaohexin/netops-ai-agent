"""Deterministic Offline Mock LLM Provider for unit and integration testing."""

from __future__ import annotations
import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar
from pydantic import BaseModel
from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage, LLMConfig
from langgraph_netagent.llm.parser import build_reflection_prompt, parse_and_validate

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class MockLLMProvider(BaseLLMProvider):
    """Deterministic, zero-network mock provider with canned responses and fault injection."""

    def __init__(self, config: Optional[LLMConfig] = None):
        cfg = config or LLMConfig(provider_type="mock", model_name="mock-qwen-7b")
        super().__init__(cfg)
        self.canned_responses: List[Any] = []
        self.pattern_handlers: Dict[str, Callable[[str], Any]] = {}
        self.fault_injection_counter: int = 0
        self.invocations: List[List[ChatMessage]] = []

    def register_canned_response(self, response: Any) -> None:
        """Queue a canned response (Pydantic model, raw JSON string, dict, or Exception)."""
        self.canned_responses.append(response)

    def register_pattern(self, pattern: str, handler: Callable[[str], Any]) -> None:
        """Register a keyword or phrase handler."""
        self.pattern_handlers[pattern.lower()] = handler

    def set_fault_injection(self, fail_count: int) -> None:
        """Instruct provider to return broken JSON for the next `fail_count` invocations."""
        self.fault_injection_counter = fail_count

    def clear(self) -> None:
        """Reset state, canned queue, and pattern handlers."""
        self.canned_responses.clear()
        self.pattern_handlers.clear()
        self.fault_injection_counter = 0
        self.invocations.clear()

    def chat(self, messages: List[ChatMessage], **kwargs: Any) -> str:
        """Execute deterministic chat completion."""
        # Deep copy messages to track exact invocation snapshot
        self.invocations.append([ChatMessage(role=m.role, content=m.content) for m in messages])
        last_prompt = messages[-1].content if messages else ""

        # Fault injection mode: simulate broken/truncated JSON output
        if self.fault_injection_counter > 0:
            self.fault_injection_counter -= 1
            return '{"invalid_json_missing_brace": true, "error_injected": "syntax_cut_off"'

        # FIFO canned queue takes priority
        if self.canned_responses:
            item = self.canned_responses.pop(0)
            if isinstance(item, Exception):
                raise item
            if isinstance(item, BaseModel):
                return item.model_dump_json()
            if isinstance(item, dict):
                return json.dumps(item)
            return str(item)

        # Keyword pattern matching
        last_lower = last_prompt.lower()
        for pattern, handler in self.pattern_handlers.items():
            if pattern in last_lower:
                result = handler(last_prompt)
                if isinstance(result, Exception):
                    raise result
                if isinstance(result, BaseModel):
                    return result.model_dump_json()
                if isinstance(result, dict):
                    return json.dumps(result)
                return str(result)

        # Default empty JSON object
        return "{}"

    async def achat(self, messages: List[ChatMessage], **kwargs: Any) -> str:
        """Asynchronous execution of chat completion."""
        return self.chat(messages, **kwargs)

    def generate_structured(
        self,
        messages: List[ChatMessage],
        response_schema: Type[T],
        max_retries: Optional[int] = None,
        **kwargs: Any
    ) -> T:
        """Execute structured generation with reflection retry self-healing."""
        retries = max_retries if max_retries is not None else self.config.max_retries
        history = [ChatMessage(role=m.role, content=m.content) for m in messages]

        for attempt in range(retries + 1):
            raw = self.chat(history, **kwargs)
            instance, err = parse_and_validate(raw, response_schema)
            if instance is not None:
                return instance

            if attempt == retries:
                raise ValueError(
                    f"MockLLMProvider: failed validation for {response_schema.__name__} after {retries} retries. Last error: {err}"
                )

            # Reflection prompt appending to history for next attempt
            logger.info("MockLLMProvider: reflection attempt %d/%d due to: %s", attempt + 1, retries, err)
            history.append(ChatMessage(role="assistant", content=raw))
            reflection = build_reflection_prompt(raw, err or "Schema validation failed", response_schema)
            history.append(ChatMessage(role="user", content=reflection))

        raise RuntimeError("Unreachable loop state in MockLLMProvider")

    async def agenerate_structured(
        self,
        messages: List[ChatMessage],
        response_schema: Type[T],
        max_retries: Optional[int] = None,
        **kwargs: Any
    ) -> T:
        """Asynchronous structured generation with reflection retry."""
        return self.generate_structured(messages, response_schema, max_retries=max_retries, **kwargs)
