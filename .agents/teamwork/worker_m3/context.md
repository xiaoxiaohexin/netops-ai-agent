# Worker Milestone 3 Context
Task: Implement Two-Stage Diagnosis, AAL Sandbox Validation & Live Patching for Buffer Overlimits / Overload (R3).
Target Files:
- langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py (diagnostic_stage1_node, diagnostic_stage2_node, sandbox_validation_node, live_hot_patch_node, re_verification_node)
- langgraph_netagent/tests/test_overload_healing_full_cycle.py (new integration tests)
Reference Files:
- langgraph_netagent/langgraph_netagent/tools/sop_retriever.py (SOP-OVERLOAD-005)
- langgraph_netagent/langgraph_netagent/tools/aal.py (AgentAccessLayer)
- langgraph_netagent/langgraph_netagent/tools/sandbox.py (ShadowSandbox)
- langgraph_netagent/langgraph_netagent/tools/fault_injector.py & mock_engine.py
- e:\netops-ai-agent\.agents\teamwork\worker_m2\handoff.md
