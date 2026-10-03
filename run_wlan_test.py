import os
import sys

# Ensure langgraph_netagent is in the path
sys.path.insert(0, r"e:\netops-ai-agent\langgraph_netagent")

from langgraph_netagent.tools.nic_adapter import LiveNICAdapter
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.workflow.day2_graph import run_day2_workflow

def test_wlan_day2():
    print("Initializing LiveNICAdapter for WLAN...")
    adapter = LiveNICAdapter(interface_name="WLAN")
    
    print("Initializing Mock LLM...")
    llm = MockLLMProvider()
    
    print("Running Day-2 workflow on WLAN...")
    state = run_day2_workflow(
        llm_provider=llm,
        lab_adapter=adapter,
        lab_name="WLAN",
        max_retries=3,
        auto_approve=True,
    )
    
    print(f"Workflow finished with status: {state.get('status')}")

if __name__ == "__main__":
    test_wlan_day2()
