"""Comprehensive tests for LLM providers (Mock, Qwen/OpenAI, vLLM, Ollama)."""

import json
import pytest
import httpx
from pydantic import BaseModel, Field
from langgraph_netagent.llm.base import ChatMessage, LLMConfig
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.llm.providers.ollama_provider import OllamaProvider
from langgraph_netagent.llm.providers.qwen_openai import QwenOpenAIProvider
from langgraph_netagent.llm.providers.vllm_provider import VLLMProvider
from langgraph_netagent.models.intent import NodeIntent


class SimpleOutput(BaseModel):
    message: str
    status: str = Field(default="ok")


class TestMockLLMProvider:
    """Test suite for deterministic MockLLMProvider."""

    def test_mock_chat_default(self, mock_llm: MockLLMProvider):
        messages = [ChatMessage(role="user", content="hello")]
        response = mock_llm.chat(messages)
        assert response == "{}"
        assert len(mock_llm.invocations) == 1
        assert mock_llm.model_name == "test-mock-llm"

    @pytest.mark.asyncio
    async def test_mock_achat(self, mock_llm: MockLLMProvider):
        messages = [ChatMessage(role="user", content="hello async")]
        response = await mock_llm.achat(messages)
        assert response == "{}"

    def test_canned_responses_fifo(self, mock_llm: MockLLMProvider):
        mock_llm.register_canned_response(NodeIntent(name="pc1", role="host"))
        mock_llm.register_canned_response(NodeIntent(name="frr1", role="router"))

        # First call pops pc1
        r1 = mock_llm.chat([ChatMessage(role="user", content="get first")])
        data1 = json.loads(r1)
        assert data1["name"] == "pc1"

        # Second call pops frr1
        r2 = mock_llm.chat([ChatMessage(role="user", content="get second")])
        data2 = json.loads(r2)
        assert data2["name"] == "frr1"

        # Third call falls back to default "{}"
        r3 = mock_llm.chat([ChatMessage(role="user", content="get third")])
        assert r3 == "{}"

    def test_canned_response_dict_and_str(self, mock_llm: MockLLMProvider):
        mock_llm.register_canned_response({"custom": "data"})
        mock_llm.register_canned_response("raw-string-response")

        r1 = mock_llm.chat([ChatMessage(role="user", content="dict test")])
        assert json.loads(r1)["custom"] == "data"

        r2 = mock_llm.chat([ChatMessage(role="user", content="str test")])
        assert r2 == "raw-string-response"

    def test_canned_response_exception(self, mock_llm: MockLLMProvider):
        mock_llm.register_canned_response(RuntimeError("Simulated LLM outage"))
        with pytest.raises(RuntimeError) as exc:
            mock_llm.chat([ChatMessage(role="user", content="crash")])
        assert "Simulated LLM outage" in str(exc.value)

    def test_pattern_matching(self, mock_llm: MockLLMProvider):
        mock_llm.register_pattern("diagnose", lambda prompt: SimpleOutput(message="Diagnosed root cause", status="fixed"))

        messages = [ChatMessage(role="user", content="Please diagnose the packet loss on frr1")]
        response = mock_llm.chat(messages)
        parsed = SimpleOutput.model_validate_json(response)
        assert parsed.status == "fixed"
        assert "Diagnosed" in parsed.message

    def test_generate_structured_success(self, mock_llm: MockLLMProvider):
        mock_llm.register_canned_response(NodeIntent(name="srl1", role="router"))
        result = mock_llm.generate_structured(
            [ChatMessage(role="user", content="make node")],
            response_schema=NodeIntent,
        )
        assert isinstance(result, NodeIntent)
        assert result.name == "srl1"
        assert result.role == "router"

    @pytest.mark.asyncio
    async def test_agenerate_structured_success(self, mock_llm: MockLLMProvider):
        mock_llm.register_canned_response(NodeIntent(name="async-node", role="leaf"))
        result = await mock_llm.agenerate_structured(
            [ChatMessage(role="user", content="make async node")],
            response_schema=NodeIntent,
        )
        assert isinstance(result, NodeIntent)
        assert result.name == "async-node"

    def test_fault_injection_and_reflection_recovery(self, mock_llm: MockLLMProvider):
        """Simulate initial broken JSON syntax followed by successful reflection repair."""
        # Step 1: Inject 1 failure (returns broken JSON on attempt 1)
        mock_llm.set_fault_injection(1)

        # Step 2: Queue valid canned response for attempt 2 (after reflection prompt)
        mock_llm.register_canned_response(NodeIntent(name="repaired-node", role="switch"))

        messages = [ChatMessage(role="user", content="generate switch node")]
        result = mock_llm.generate_structured(messages, response_schema=NodeIntent, max_retries=3)

        assert isinstance(result, NodeIntent)
        assert result.name == "repaired-node"
        assert result.role == "switch"

        # Verify that 2 invocations occurred
        assert len(mock_llm.invocations) == 2
        # The second invocation must contain the reflection prompt generated by parser
        second_call_messages = mock_llm.invocations[1]
        assert len(second_call_messages) == 3
        assert second_call_messages[1].role == "assistant"
        assert second_call_messages[2].role == "user"
        assert "--- ERROR ---" in second_call_messages[2].content

    def test_retry_exhaustion_raises(self, mock_llm: MockLLMProvider):
        """Ensure provider raises ValueError when retries are exhausted."""
        mock_llm.set_fault_injection(5)  # Will fail 5 times
        messages = [ChatMessage(role="user", content="fail test")]

        with pytest.raises(ValueError) as exc:
            mock_llm.generate_structured(messages, response_schema=NodeIntent, max_retries=2)
        assert "failed validation for NodeIntent after 2 retries" in str(exc.value)

    def test_clear_resets_state(self, mock_llm: MockLLMProvider):
        mock_llm.register_canned_response("item")
        mock_llm.set_fault_injection(2)
        mock_llm.chat([ChatMessage(role="user", content="foo")])
        mock_llm.clear()
        assert len(mock_llm.canned_responses) == 0
        assert mock_llm.fault_injection_counter == 0
        assert len(mock_llm.invocations) == 0


class TestRemoteProvidersMockTransport:
    """Test suite for QwenOpenAI, vLLM, and Ollama providers with mock HTTP transport."""

    def test_qwen_openai_provider_chat_and_structured(self):
        def handler(request: httpx.Request) -> httpx.Response:
            req_data = json.loads(request.content)
            assert req_data["response_format"] == {"type": "json_object"}
            assert req_data["model"] == "qwen2.5-coder-32b-instruct"
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": '{"name": "qwen-node", "role": "router"}',
                            }
                        }
                    ]
                },
            )

        provider = QwenOpenAIProvider(
            config=LLMConfig(
                provider_type="openai",
                model_name="qwen2.5-coder-32b-instruct",
                api_key="sk-test-token",
            )
        )
        provider.client = httpx.Client(
            base_url=provider.base_url,
            headers=provider._get_headers(),
            transport=httpx.MockTransport(handler),
        )

        # Chat execution test
        raw = provider.chat([ChatMessage(role="user", content="create router")])
        assert "qwen-node" in raw

        # Structured generation test
        obj = provider.generate_structured([ChatMessage(role="user", content="create router")], NodeIntent)
        assert obj.name == "qwen-node"
        assert obj.role == "router"

    @pytest.mark.asyncio
    async def test_qwen_openai_provider_achat_and_agenerate(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": '{"name": "async-qwen", "role": "router"}',
                            }
                        }
                    ]
                },
            )

        provider = QwenOpenAIProvider(
            config=LLMConfig(
                provider_type="openai",
                model_name="qwen2.5-coder-32b-instruct",
                api_key="sk-test-token",
            )
        )
        provider.async_client = httpx.AsyncClient(
            base_url=provider.base_url,
            headers=provider._get_headers(),
            transport=httpx.MockTransport(handler),
        )

        raw = await provider.achat([ChatMessage(role="user", content="async chat")])
        assert "async-qwen" in raw

        obj = await provider.agenerate_structured([ChatMessage(role="user", content="async gen")], NodeIntent)
        assert obj.name == "async-qwen"

    def test_qwen_openai_reflection_retry(self):
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                # Return invalid syntax first
                return httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {
                                    "role": "assistant",
                                    "content": '{"broken": [',
                                }
                            }
                        ]
                    },
                )
            else:
                # Return valid schema on reflection retry
                return httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {
                                    "role": "assistant",
                                    "content": '{"name": "retry-node", "role": "host"}',
                                }
                            }
                        ]
                    },
                )

        provider = QwenOpenAIProvider()
        provider.client = httpx.Client(
            base_url=provider.base_url,
            headers=provider._get_headers(),
            transport=httpx.MockTransport(handler),
        )

        obj = provider.generate_structured([ChatMessage(role="user", content="make node")], NodeIntent, max_retries=2)
        assert obj.name == "retry-node"
        assert calls == 2

    def test_vllm_provider_guided_json_injection(self):
        def handler(request: httpx.Request) -> httpx.Response:
            req_data = json.loads(request.content)
            # Verify guided_json was injected into extra_body
            assert "extra_body" in req_data
            assert "guided_json" in req_data["extra_body"]
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": '{"name": "vllm-node", "role": "leaf"}',
                            }
                        }
                    ]
                },
            )

        provider = VLLMProvider(
            config=LLMConfig(
                provider_type="vllm",
                model_name="qwen-coder",
                base_url="http://test-vllm:8000/v1",
            )
        )
        provider.client = httpx.Client(
            base_url=provider.base_url,
            headers=provider._get_headers(),
            transport=httpx.MockTransport(handler),
        )

        obj = provider.generate_structured([ChatMessage(role="user", content="make leaf")], NodeIntent)
        assert obj.name == "vllm-node"
        assert obj.role == "leaf"

    @pytest.mark.asyncio
    async def test_vllm_provider_achat(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": "vllm ok"}}]},
            )

        provider = VLLMProvider()
        provider.async_client = httpx.AsyncClient(
            base_url=provider.base_url,
            transport=httpx.MockTransport(handler),
        )
        res = await provider.achat([ChatMessage(role="user", content="ping")])
        assert res == "vllm ok"

    def test_ollama_provider_format_schema(self):
        def handler(request: httpx.Request) -> httpx.Response:
            req_data = json.loads(request.content)
            # Verify format schema was included
            assert "format" in req_data
            assert "properties" in req_data["format"]
            return httpx.Response(
                200,
                json={"message": {"role": "assistant", "content": '{"name": "ollama-node", "role": "spine"}'}},
            )

        provider = OllamaProvider(
            config=LLMConfig(
                provider_type="ollama",
                model_name="qwen2.5-coder:32b",
                base_url="http://test-ollama:11434",
            )
        )
        provider.client = httpx.Client(
            base_url=provider.base_url,
            transport=httpx.MockTransport(handler),
        )

        obj = provider.generate_structured([ChatMessage(role="user", content="make spine")], NodeIntent)
        assert obj.name == "ollama-node"
        assert obj.role == "spine"

    @pytest.mark.asyncio
    async def test_ollama_provider_achat(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"message": {"role": "assistant", "content": "ollama ok"}},
            )

        provider = OllamaProvider()
        provider.async_client = httpx.AsyncClient(
            base_url=provider.base_url,
            transport=httpx.MockTransport(handler),
        )
        res = await provider.achat([ChatMessage(role="user", content="ping")])
        assert res == "ollama ok"
