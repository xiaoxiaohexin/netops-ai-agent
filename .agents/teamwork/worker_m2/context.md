# Worker Milestone 2 Context
Task: Implement Telemetry Node & Anomaly Classifier in langgraph_netagent (R2).
Target Files:
- langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py (telemetry_extraction_node and helper classification logic)
- langgraph_netagent/langgraph_netagent/workflow/operational_state.py (anomaly_classification field if needed)
- langgraph_netagent/tests/test_operational_r2_telemetry.py (new unit and integration tests)
Reference Files:
- langgraph_netagent/langgraph_netagent/models/operational.py (AnomalyClassification, FiveTuple)
- langgraph_netagent/langgraph_netagent/models/telemetry.py (QdiscTelemetry, NetworkHealthReport)
- langgraph_netagent/langgraph_netagent/tools/probes.py (QdiscProbe, NetworkTelemetryCollector)
- e:\netops-ai-agent\.agents\teamwork\explorer_survey_2\handoff.md (Section 4.3)
