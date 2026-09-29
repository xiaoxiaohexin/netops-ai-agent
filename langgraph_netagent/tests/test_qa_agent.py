"""Unit Tests for SimpleQAAgent with Live/Mock Containerlab Topology Context."""

from pathlib import Path
from typing import List
import pytest

from langgraph_netagent.llm.base import ChatMessage, LLMConfig
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.qa_agent import SimpleQAAgent


class RecordingLLMProvider(MockLLMProvider):
    """Mock LLM provider that captures sent messages for inspection."""

    def __init__(self):
        super().__init__()
        self.last_messages: List[ChatMessage] = []

    def chat(self, messages: List[ChatMessage], **kwargs) -> str:
        self.last_messages = list(messages)
        return "Mock response regarding network topology."


def test_qa_agent_without_adapter():
    provider = RecordingLLMProvider()
    qa = SimpleQAAgent(llm_provider=provider)
    resp = qa.answer("什么是 BGP Unnumbered?")
    assert "Mock response" in resp
    assert len(provider.last_messages) >= 2
    system_msg = provider.last_messages[0].content
    assert "通用网络技术" in system_msg


def test_qa_agent_with_adapter_injects_topology():
    adapter = MockContainerlabAdapter()
    for candidate in [
        Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml",
        Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml",
    ]:
        if candidate.exists():
            adapter.deploy(candidate)
            break

    provider = RecordingLLMProvider()
    qa = SimpleQAAgent(llm_provider=provider, lab_adapter=adapter)
    resp = qa.answer("当前网络的拓扑是什么样的")

    assert "Mock response" in resp
    system_msg = provider.last_messages[0].content
    assert "当前运行中的真实网络环境与拓扑底座" in system_msg
    assert "pc1" in system_msg or "frr1" in system_msg or "mock-lab" in system_msg
    assert "切勿回答'无法确定'" in system_msg


def test_qa_agent_executes_action_and_records_memory():
    adapter = MockContainerlabAdapter()
    for candidate in [
        Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml",
        Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml",
    ]:
        if candidate.exists():
            adapter.deploy(candidate)
            break

    class ActionEmittingLLMProvider(MockLLMProvider):
        def __init__(self):
            super().__init__()
            self.turn = 0

        def chat(self, messages: List[ChatMessage], **kwargs) -> str:
            self.turn += 1
            if self.turn == 1:
                return (
                    "```action\n"
                    "node: pc1\n"
                    "command: ip route add 10.99.0.0/24 dev eth1\n"
                    "verify: ip route show 10.99.0.0/24\n"
                    "description: 在 pc1 配置 10.99.0.0/24 测试路由\n"
                    "```"
                )
            return "确认收到，当前服务运行正常。"

    provider = ActionEmittingLLMProvider()
    qa = SimpleQAAgent(llm_provider=provider, lab_adapter=adapter)

    # Turn 1: Action execution
    resp1 = qa.answer("在pc1添加静态路由10.99.0.0/24")
    assert "Day-2 闭环执行中" in resp1
    assert "安全审计" in resp1
    assert len(qa.memory.recent_actions) == 1
    assert qa.memory.recent_actions[0]["node"] == "pc1"

    # Turn 2: Followup query checks memory
    resp2 = qa.answer("检查刚才配置的状态")
    assert "确认收到" in resp2
    assert len(qa.memory.history) >= 2


def test_qa_agent_with_nic_adapter_injects_real_nic_topology():
    from langgraph_netagent.tools.nic_adapter import LiveNICAdapter
    nic = LiveNICAdapter(interface_name="VMware Network Adapter VMnet8")
    provider = RecordingLLMProvider()
    qa = SimpleQAAgent(llm_provider=provider, lab_adapter=nic)
    resp = qa.answer("介绍当前网络")
    assert "Mock response" in resp
    system_msg = provider.last_messages[0].content
    assert "当前接入的真实网卡网络拓扑与在线资产" in system_msg
    assert "VMware Network Adapter VMnet8" in system_msg
    assert "绝对不要套用虚构的 Containerlab 或 CLOS 节点" in system_msg


def test_qa_agent_adapter_setter_updates_context():
    from langgraph_netagent.tools.nic_adapter import LiveNICAdapter
    adapter = MockContainerlabAdapter()
    provider = RecordingLLMProvider()
    qa = SimpleQAAgent(llm_provider=provider, lab_adapter=adapter)

    # Switch to NIC adapter via property setter
    nic = LiveNICAdapter(interface_name="WLAN")
    qa.lab_adapter = nic
    assert qa.adapter == nic
    assert qa.aal is not None

    qa.answer("查询网关")
    system_msg = provider.last_messages[0].content
    assert "WLAN" in system_msg
    assert "真实物理/虚拟网卡网络" in system_msg

