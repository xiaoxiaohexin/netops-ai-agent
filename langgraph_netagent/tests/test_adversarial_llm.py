"""Adversarial stress-test suite for LLM Providers and Reflection Mechanics.

Authored by challenger_net_m1_2:
1. Concurrency and state isolation on MockLLMProvider
2. Fault injection counter and multi-step reflection repair within retry limits
3. Exceeding max_retries boundary conditions and exception enforcement
4. Remote provider request configuration and HTTP/transport error resilience
"""

import asyncio
import json
import pytest
import httpx
from pydantic import BaseModel, Field
from typing import Any, List

from langgraph_netagent.llm.base import ChatMessage, LLMConfig
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.llm.providers.ollama_provider import OllamaProvider
from langgraph_netagent.llm.providers.qwen_openai import QwenOpenAIProvider
from langgraph_netagent.llm.providers.vllm_provider import VLLMProvider
from langgraph_netagent.models.intent import NodeIntent, LinkIntent, NetworkIntent
from langgraph_netagent.models.topology import ContainerlabLinkEndpoint, DeviceConfigFile


# Test Schema for stress testing
class CustomValidationModel(BaseModel):
    name: str = Field(..., min_length=3, max_length=15)
    port_count: int = Field(..., ge=1, le=64)
    enabled: bool = Field(default=True)


class TestMockLLMProviderConcurrencyAndIsolation:
    """Objective 1: Concurrency and State Isolation Stress Tests."""

    @pytest.mark.asyncio
    async def test_concurrent_async_calls_with_pattern_matching(self):
        """Verify that 60 concurrent async calls match their respective patterns without cross-talk."""
        provider = MockLLMProvider(LLMConfig(provider_type="mock", model_name="concurrency-test"))

        provider.register_pattern("alpha", lambda p: NodeIntent(name="node-alpha", role="router"))
        provider.register_pattern("beta", lambda p: NodeIntent(name="node-beta", role="switch"))
        provider.register_pattern("gamma", lambda p: NodeIntent(name="node-gamma", role="host"))

        async def worker(prefix: str, index: int) -> NodeIntent:
            prompt = f"Request for {prefix} worker #{index}"
            return await provider.agenerate_structured(
                [ChatMessage(role="user", content=prompt)],
                response_schema=NodeIntent,
            )

        # Launch 60 concurrent requests (20 of each pattern)
        tasks = []
        for i in range(20):
            tasks.append(worker("alpha", i))
            tasks.append(worker("beta", i))
            tasks.append(worker("gamma", i))

        results = await asyncio.gather(*tasks)

        assert len(results) == 60
        for i, res in enumerate(results):
            expected_role = ["router", "switch", "host"][i % 3]
            expected_name = [f"node-alpha", f"node-beta", f"node-gamma"][i % 3]
            assert res.name == expected_name
            assert res.role == expected_role

        assert len(provider.invocations) == 60

    def test_multi_instance_state_isolation(self):
        """Verify that multiple MockLLMProvider instances are strictly isolated."""
        p1 = MockLLMProvider()
        p2 = MockLLMProvider()
        p3 = MockLLMProvider()

        # Mutate p1
        p1.set_fault_injection(5)
        p1.register_canned_response("p1-canned")

        # Mutate p2
        p2.register_pattern("target", lambda p: "p2-pattern")

        # Mutate p3
        p3.register_canned_response("p3-canned")

        # Verify p1 state
        assert p1.fault_injection_counter == 5
        assert len(p1.canned_responses) == 1
        assert len(p1.pattern_handlers) == 0

        # Verify p2 state
        assert p2.fault_injection_counter == 0
        assert len(p2.canned_responses) == 0
        assert len(p2.pattern_handlers) == 1

        # Verify p3 state
        assert p3.fault_injection_counter == 0
        assert len(p3.canned_responses) == 1
        assert len(p3.pattern_handlers) == 0

        # Execute on p1, p2, p3
        resp1 = p1.chat([ChatMessage(role="user", content="hello")])
        assert "syntax_cut_off" in resp1
        assert p1.fault_injection_counter == 4

        resp2 = p2.chat([ChatMessage(role="user", content="target message")])
        assert resp2 == "p2-pattern"

        resp3 = p3.chat([ChatMessage(role="user", content="anything")])
        assert resp3 == "p3-canned"

        # Check invocations isolation
        assert len(p1.invocations) == 1
        assert len(p2.invocations) == 1
        assert len(p3.invocations) == 1

    @pytest.mark.asyncio
    async def test_concurrent_structured_calls_isolated_reflection_histories(self):
        """Verify that concurrent calls undergoing reflection do not leak retry histories across tasks."""
        provider = MockLLMProvider()

        # Pattern for task A: fails on first attempt, repairs on reflection
        def handler_a(prompt: str) -> str:
            if "--- ERROR ---" in prompt:
                return '{"name": "repaired-a", "role": "router"}'
            return '{"task-a-broken": '

        # Pattern for task B: succeeds immediately
        def handler_b(prompt: str) -> str:
            return '{"name": "immediate-b", "role": "switch"}'

        provider.register_pattern("task-a", handler_a)
        provider.register_pattern("task-b", handler_b)

        async def run_a():
            return await provider.agenerate_structured(
                [ChatMessage(role="user", content="Execute task-a now")],
                response_schema=NodeIntent,
                max_retries=2,
            )

        async def run_b():
            return await provider.agenerate_structured(
                [ChatMessage(role="user", content="Execute task-b now")],
                response_schema=NodeIntent,
                max_retries=2,
            )

        res_a, res_b = await asyncio.gather(run_a(), run_b())

        assert res_a.name == "repaired-a"
        assert res_b.name == "immediate-b"

        # Find invocations corresponding to task-a and task-b
        calls_a = [inv for inv in provider.invocations if any("task-a" in m.content for m in inv)]
        calls_b = [inv for inv in provider.invocations if any("task-b" in m.content for m in inv)]

        assert len(calls_a) == 2  # initial + reflection
        assert len(calls_b) == 1  # initial only

        # Verify task-b invocation NEVER saw task-a's reflection error
        for msg in calls_b[0]:
            assert "task-a" not in msg.content
            assert "--- ERROR ---" not in msg.content


class TestFaultInjectionAndReflectionRetry:
    """Objective 2: Fault Injection Counter and Reflection Repair Mechanics."""

    def test_reflection_prompt_exact_structure(self):
        """Verify that the reflection prompt contains exact error diagnostics, excerpt, and schema."""
        provider = MockLLMProvider()
        provider.set_fault_injection(1)
        provider.register_canned_response(NodeIntent(name="fixed-node", role="leaf"))

        res = provider.generate_structured(
            [ChatMessage(role="user", content="create leaf node")],
            response_schema=NodeIntent,
            max_retries=2,
        )

        assert res.name == "fixed-node"
        assert len(provider.invocations) == 2

        # Inspect the reflection invocation
        second_call = provider.invocations[1]
        assert len(second_call) == 3
        orig_msg, assistant_msg, reflection_msg = second_call

        assert orig_msg.role == "user"
        assert orig_msg.content == "create leaf node"

        assert assistant_msg.role == "assistant"
        assert "syntax_cut_off" in assistant_msg.content

        assert reflection_msg.role == "user"
        assert "--- ERROR ---" in reflection_msg.content
        assert "JSON Extraction Error" in reflection_msg.content
        assert "--- YOUR PREVIOUS OUTPUT (EXCERPT) ---" in reflection_msg.content
        assert "syntax_cut_off" in reflection_msg.content
        assert "NodeIntent" in reflection_msg.content or "properties" in reflection_msg.content
        assert "```json" in reflection_msg.content

    def test_multi_step_reflection_repair_boundary(self):
        """Verify that fault_injection=2 with max_retries=2 repairs on the 3rd attempt."""
        provider = MockLLMProvider()
        # Injects 2 faults, so attempt 0 fails, attempt 1 fails, attempt 2 succeeds
        provider.set_fault_injection(2)
        provider.register_canned_response(NodeIntent(name="boundary-node", role="spine"))

        res = provider.generate_structured(
            [ChatMessage(role="user", content="make spine")],
            response_schema=NodeIntent,
            max_retries=2,
        )

        assert res.name == "boundary-node"
        assert len(provider.invocations) == 3

        # First call: 1 message
        assert len(provider.invocations[0]) == 1
        # Second call: 3 messages (orig + fail1 + reflection1)
        assert len(provider.invocations[1]) == 3
        # Third call: 5 messages (orig + fail1 + reflection1 + fail2 + reflection2)
        assert len(provider.invocations[2]) == 5
        assert provider.invocations[2][3].role == "assistant"
        assert provider.invocations[2][4].role == "user"
        assert "--- ERROR ---" in provider.invocations[2][4].content

    def test_semantic_schema_validation_error_reflection(self):
        """Verify that semantic Pydantic validation failures (e.g. constraints) trigger targeted reflection."""
        provider = MockLLMProvider()

        # Step 1: LLM outputs valid JSON, but violates CustomValidationModel constraints (name too short, port_count > 64)
        bad_semantic_output = '{"name": "ab", "port_count": 128, "enabled": true}'
        # Step 2: LLM outputs valid model on reflection
        repaired_output = CustomValidationModel(name="switch-01", port_count=48, enabled=True)

        provider.register_canned_response(bad_semantic_output)
        provider.register_canned_response(repaired_output)

        res = provider.generate_structured(
            [ChatMessage(role="user", content="configure switch")],
            response_schema=CustomValidationModel,
            max_retries=2,
        )

        assert res.name == "switch-01"
        assert res.port_count == 48
        assert len(provider.invocations) == 2

        # Verify the reflection prompt highlighted the specific schema errors
        reflection_prompt = provider.invocations[1][2].content
        assert "Schema Validation Error" in reflection_prompt
        assert "Field 'name'" in reflection_prompt
        assert "Field 'port_count'" in reflection_prompt


class TestExceedingMaxRetriesExceptionHandling:
    """Objective 3: Verify exceeding max_retries raises clean exceptions without returning corrupt models."""

    def test_mock_exhaustion_raises_value_error(self):
        """When fault_injection exceeds max_retries, ensure ValueError is raised with full diagnostic message."""
        provider = MockLLMProvider()
        provider.set_fault_injection(3)

        with pytest.raises(ValueError) as exc:
            provider.generate_structured(
                [ChatMessage(role="user", content="will exhaust")],
                response_schema=NodeIntent,
                max_retries=2,  # 3 attempts (0, 1, 2) all fail
            )

        err_msg = str(exc.value)
        assert "failed validation for NodeIntent after 2 retries" in err_msg
        assert "JSON Extraction Error" in err_msg
        assert len(provider.invocations) == 3

    @pytest.mark.asyncio
    async def test_mock_async_exhaustion_raises_value_error(self):
        """Async variant of retry exhaustion."""
        provider = MockLLMProvider()
        provider.set_fault_injection(2)

        with pytest.raises(ValueError) as exc:
            await provider.agenerate_structured(
                [ChatMessage(role="user", content="async exhaust")],
                response_schema=NodeIntent,
                max_retries=1,
            )

        assert "failed validation for NodeIntent after 1 retries" in str(exc.value)
        assert len(provider.invocations) == 2

    def test_boundary_zero_retries_fails_immediately(self):
        """max_retries=0 must fail on the very first attempt without appending reflection."""
        provider = MockLLMProvider()
        provider.set_fault_injection(1)

        with pytest.raises(ValueError) as exc:
            provider.generate_structured(
                [ChatMessage(role="user", content="no retries allowed")],
                response_schema=NodeIntent,
                max_retries=0,
            )

        assert "after 0 retries" in str(exc.value)
        assert len(provider.invocations) == 1

    def test_non_json_conversational_exhaustion(self):
        """Verify LLM repeatedly answering with conversational refusal cleanly exhausts and raises."""
        provider = MockLLMProvider()
        refusal = "I apologize, but as an AI assistant I cannot produce YAML or JSON."
        provider.register_canned_response(refusal)
        provider.register_canned_response(refusal)

        with pytest.raises(ValueError) as exc:
            provider.generate_structured(
                [ChatMessage(role="user", content="give json")],
                response_schema=NodeIntent,
                max_retries=1,
            )

        assert "No JSON opening bracket" in str(exc.value)
        assert len(provider.invocations) == 2

    def test_remote_providers_exhaustion_raise_value_error(self):
        """Verify QwenOpenAI, VLLM, and Ollama all raise ValueError when retries are exhausted."""
        def bad_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "choices": [{"message": {"role": "assistant", "content": '{"broken_json": '}}],
                    "message": {"role": "assistant", "content": '{"broken_json": '},
                },
            )

        # 1. QwenOpenAIProvider
        qwen = QwenOpenAIProvider()
        qwen.client = httpx.Client(base_url=qwen.base_url, transport=httpx.MockTransport(bad_handler))
        with pytest.raises(ValueError) as exc:
            qwen.generate_structured([ChatMessage(role="user", content="qwen")], NodeIntent, max_retries=1)
        assert "QwenOpenAIProvider: failed validation for NodeIntent after 1 retries" in str(exc.value)

        # 2. VLLMProvider
        vllm = VLLMProvider()
        vllm.client = httpx.Client(base_url=vllm.base_url, transport=httpx.MockTransport(bad_handler))
        with pytest.raises(ValueError) as exc:
            vllm.generate_structured([ChatMessage(role="user", content="vllm")], NodeIntent, max_retries=1)
        assert "VLLMProvider: failed validation for NodeIntent after 1 retries" in str(exc.value)

        # 3. OllamaProvider
        ollama = OllamaProvider()
        ollama.client = httpx.Client(base_url=ollama.base_url, transport=httpx.MockTransport(bad_handler))
        with pytest.raises(ValueError) as exc:
            ollama.generate_structured([ChatMessage(role="user", content="ollama")], NodeIntent, max_retries=1)
        assert "OllamaProvider: failed validation for NodeIntent after 1 retries" in str(exc.value)


class TestRemoteProvidersConfigAndHttpErrors:
    """Objective 4: Request configuration and HTTP/Transport error handling."""

    @pytest.mark.parametrize("status_code", [400, 401, 403, 404, 429, 500, 502, 503, 504])
    def test_qwen_openai_http_status_errors(self, status_code: int):
        """Verify QwenOpenAI raises httpx.HTTPStatusError for all HTTP error codes without swallowing."""
        def error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, json={"error": {"code": status_code, "message": "Failed"}})

        provider = QwenOpenAIProvider()
        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(error_handler))

        # Chat
        with pytest.raises(httpx.HTTPStatusError) as exc:
            provider.chat([ChatMessage(role="user", content="test")])
        assert exc.value.response.status_code == status_code

        # Structured generation must NOT catch or swallow HTTP errors
        with pytest.raises(httpx.HTTPStatusError) as exc:
            provider.generate_structured([ChatMessage(role="user", content="test")], NodeIntent)
        assert exc.value.response.status_code == status_code

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [401, 429, 500])
    async def test_qwen_openai_async_http_errors(self, status_code: int):
        """Verify async QwenOpenAI raises HTTPStatusError."""
        def error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, text="Error")

        provider = QwenOpenAIProvider()
        provider.async_client = httpx.AsyncClient(base_url=provider.base_url, transport=httpx.MockTransport(error_handler))

        with pytest.raises(httpx.HTTPStatusError):
            await provider.achat([ChatMessage(role="user", content="test")])

        with pytest.raises(httpx.HTTPStatusError):
            await provider.agenerate_structured([ChatMessage(role="user", content="test")], NodeIntent)

    def test_vllm_request_configuration_and_http_errors(self):
        """Verify vLLM payload structure (extra_body.guided_json) and error handling."""
        captured_payload = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload
            captured_payload = json.loads(request.content)
            assert request.url.path == "/v1/chat/completions"
            assert request.headers["Authorization"] == "Bearer sk-vllm-secret"
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": '{"name": "vnode", "role": "router"}'}}]})

        provider = VLLMProvider(
            LLMConfig(
                provider_type="vllm",
                model_name="Qwen-32B",
                base_url="http://vllm-cluster:8000/v1",
                api_key="sk-vllm-secret",
                temperature=0.3,
            )
        )
        provider.client = httpx.Client(
            base_url=provider.base_url,
            headers=provider._get_headers(),
            transport=httpx.MockTransport(handler),
        )

        res = provider.generate_structured([ChatMessage(role="user", content="test vllm")], NodeIntent)
        assert res.name == "vnode"
        assert captured_payload["model"] == "Qwen-32B"
        assert captured_payload["temperature"] == 0.3
        assert "guided_json" in captured_payload["extra_body"]
        assert "properties" in captured_payload["extra_body"]["guided_json"]

        # Now test 503 Service Unavailable
        def error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="vLLM Overloaded")

        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(error_handler))
        with pytest.raises(httpx.HTTPStatusError):
            provider.chat([ChatMessage(role="user", content="test")])

    def test_ollama_request_configuration_and_http_errors(self):
        """Verify Ollama payload structure (format schema, options) and 404 model not found handling."""
        captured_payload = {}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_payload
            captured_payload = json.loads(request.content)
            assert request.url.path == "/api/chat"
            return httpx.Response(200, json={"message": {"role": "assistant", "content": '{"name": "onode", "role": "switch"}'}})

        provider = OllamaProvider(
            LLMConfig(
                provider_type="ollama",
                model_name="qwen2.5-coder:32b",
                base_url="http://localhost:11434",
                temperature=0.5,
            )
        )
        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(handler))

        res = provider.generate_structured([ChatMessage(role="user", content="test ollama")], NodeIntent)
        assert res.name == "onode"
        assert captured_payload["stream"] is False
        assert captured_payload["options"]["temperature"] == 0.5
        assert "format" in captured_payload
        assert "properties" in captured_payload["format"]

        # 404 Model Not Found
        def not_found_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "model 'qwen2.5-coder:32b' not found"})

        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(not_found_handler))
        with pytest.raises(httpx.HTTPStatusError) as exc:
            provider.chat([ChatMessage(role="user", content="test")])
        assert exc.value.response.status_code == 404

    def test_transport_timeout_and_network_failure(self):
        """Verify network-level transport exceptions (Timeout, ConnectError) propagate cleanly."""
        def timeout_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Connection read timed out after 60s", request=request)

        provider = QwenOpenAIProvider()
        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(timeout_handler))

        with pytest.raises(httpx.ReadTimeout):
            provider.chat([ChatMessage(role="user", content="ping")])

        with pytest.raises(httpx.ReadTimeout):
            provider.generate_structured([ChatMessage(role="user", content="ping")], NodeIntent)

    def test_malformed_response_json_from_gateway(self):
        """Verify non-JSON response (e.g. HTML gateway error page with 200 OK) raises JSONDecodeError."""
        def html_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html><body>Cloudflare Bad Gateway</body></html>", headers={"Content-Type": "text/html"})

        provider = QwenOpenAIProvider()
        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(html_handler))

        with pytest.raises(json.JSONDecodeError):
            provider.chat([ChatMessage(role="user", content="hello")])

    def test_empty_choices_payload_raises_index_error(self):
        """Verify API response with empty choices list raises IndexError."""
        def empty_choices_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"choices": []})

        provider = QwenOpenAIProvider()
        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(empty_choices_handler))

        with pytest.raises(IndexError):
            provider.chat([ChatMessage(role="user", content="hello")])

    def test_ollama_missing_message_key_raises_key_error(self):
        """Verify Ollama response missing 'message' key raises KeyError."""
        def missing_key_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"error": "model error without message key"})

        provider = OllamaProvider()
        provider.client = httpx.Client(base_url=provider.base_url, transport=httpx.MockTransport(missing_key_handler))

        with pytest.raises(KeyError):
            provider.chat([ChatMessage(role="user", content="hello")])

    def test_negative_max_retries_raises_runtime_error(self):
        """Verify negative max_retries skips loop and raises RuntimeError unreachable state."""
        provider = MockLLMProvider()
        with pytest.raises(RuntimeError) as exc:
            provider.generate_structured([ChatMessage(role="user", content="test")], NodeIntent, max_retries=-1)
        assert "Unreachable loop state" in str(exc.value)

    def test_pattern_matching_reflection_drop_empirical_verification(self):
        """Empirically verify that MockLLMProvider only inspects messages[-1], dropping messages[0] patterns during reflection."""
        provider = MockLLMProvider()
        # Register pattern on keyword 'special-router'
        provider.register_pattern("special-router", lambda p: '{"broken_syntax": ')

        # First call has 'special-router' in user prompt
        # After broken syntax, reflection prompt is generated which does NOT have 'special-router'
        # Because chat() only checks messages[-1], pattern match fails on retry and falls back to '{}'
        with pytest.raises(ValueError) as exc:
            provider.generate_structured(
                [ChatMessage(role="user", content="Deploy special-router now")],
                response_schema=NodeIntent,
                max_retries=1,
            )
        # Verify the failure on retry was due to falling back to empty dict '{}' (missing required fields)
        assert "Field 'name': Field required" in str(exc.value)

    @pytest.mark.asyncio
    async def test_stress_100_concurrent_multi_provider_requests(self):
        """Stress-test 100 concurrent async tasks across all 4 LLM providers simultaneously."""
        # Setup mock remote handlers
        def qwen_handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": '{"name": "qwen-p", "role": "router"}'}}]})

        def vllm_handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": '{"name": "vllm-p", "role": "switch"}'}}]})

        def ollama_handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"role": "assistant", "content": '{"name": "ollama-p", "role": "host"}'}})

        mock_provider = MockLLMProvider()
        mock_provider.register_pattern("mock", lambda p: NodeIntent(name="mock-p", role="router"))

        qwen_provider = QwenOpenAIProvider()
        qwen_provider.async_client = httpx.AsyncClient(base_url=qwen_provider.base_url, transport=httpx.MockTransport(qwen_handler))

        vllm_provider = VLLMProvider()
        vllm_provider.async_client = httpx.AsyncClient(base_url=vllm_provider.base_url, transport=httpx.MockTransport(vllm_handler))

        ollama_provider = OllamaProvider()
        ollama_provider.async_client = httpx.AsyncClient(base_url=ollama_provider.base_url, transport=httpx.MockTransport(ollama_handler))

        async def worker_mock(idx: int):
            return await mock_provider.agenerate_structured([ChatMessage(role="user", content=f"mock task {idx}")], NodeIntent)

        async def worker_qwen(idx: int):
            return await qwen_provider.agenerate_structured([ChatMessage(role="user", content=f"qwen task {idx}")], NodeIntent)

        async def worker_vllm(idx: int):
            return await vllm_provider.agenerate_structured([ChatMessage(role="user", content=f"vllm task {idx}")], NodeIntent)

        async def worker_ollama(idx: int):
            return await ollama_provider.agenerate_structured([ChatMessage(role="user", content=f"ollama task {idx}")], NodeIntent)

        tasks = []
        for i in range(25):
            tasks.append(worker_mock(i))
            tasks.append(worker_qwen(i))
            tasks.append(worker_vllm(i))
            tasks.append(worker_ollama(i))

        results = await asyncio.gather(*tasks)
        assert len(results) == 100

        # Verify results correctness
        for i in range(0, 100, 4):
            assert results[i].name == "mock-p"
            assert results[i+1].name == "qwen-p"
            assert results[i+2].name == "vllm-p"
            assert results[i+3].name == "ollama-p"

