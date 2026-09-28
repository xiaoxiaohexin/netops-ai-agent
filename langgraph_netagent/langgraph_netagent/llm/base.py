"""Abstract Base LLM Provider and Core Types."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type, TypeVar
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T", bound=BaseModel)


class ChatMessage(BaseModel):
    """Standardized chat message."""
    model_config = ConfigDict(populate_by_name=True)

    role: str = Field(..., description="'system', 'user', or 'assistant'")
    content: str = Field(..., description="Message text content")


class LLMConfig(BaseModel):
    """Configuration options for initializing an LLM provider."""
    model_config = ConfigDict(populate_by_name=True)

    provider_type: str = Field(default="mock", description="'openai', 'vllm', 'ollama', 'mock'")
    model_name: str = Field(default="qwen2.5-coder-32b-instruct", description="Model name or path")
    api_key: Optional[str] = Field(default=None, description="API token / key")
    base_url: Optional[str] = Field(default=None, description="Endpoint URL")
    temperature: float = Field(default=0.0, ge=0.0, le=2.0, description="Sampling temperature")
    timeout_seconds: float = Field(default=60.0, description="HTTP request timeout in seconds")
    max_retries: int = Field(default=3, description="Schema repair reflection retry limit")


class BaseLLMProvider(ABC):
    """Abstract interface defining standard synchronous and asynchronous model invocations."""

    def __init__(self, config: LLMConfig):
        self.config = config

    @property
    def model_name(self) -> str:
        """Name of the underlying language model."""
        return self.config.model_name

    @abstractmethod
    def chat(self, messages: List[ChatMessage], **kwargs) -> str:
        """Execute chat completion returning raw response text."""
        pass

    @abstractmethod
    async def achat(self, messages: List[ChatMessage], **kwargs) -> str:
        """Asynchronous execution of chat completion."""
        pass

    @abstractmethod
    def generate_structured(
        self,
        messages: List[ChatMessage],
        response_schema: Type[T],
        max_retries: Optional[int] = None,
        **kwargs
    ) -> T:
        """Execute chat completion with automatic structured parsing and schema repair retries."""
        pass

    @abstractmethod
    async def agenerate_structured(
        self,
        messages: List[ChatMessage],
        response_schema: Type[T],
        max_retries: Optional[int] = None,
        **kwargs
    ) -> T:
        """Asynchronous structured generation with schema repair retries."""
        pass
