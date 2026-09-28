"""Unit tests for LangGraph conditional edge routing functions."""

import pytest
from langgraph_netagent.workflow.edges import (
    route_after_approval,
    route_after_deployment,
    route_after_validation,
    route_after_verification,
)
from langgraph_netagent.workflow.state import create_initial_state


class TestConditionalRoutingEdges:
    """Test suite covering edge routing transitions, retry boundaries, and circuit breaker."""

    # 1. Validation Edge
    def test_route_after_validation_success(self):
        state = create_initial_state("Intent")
        state["status"] = "validation_passed"
        state["validation_result"] = {"is_valid": True, "errors": []}
        assert route_after_validation(state) == "human_approval"

    def test_route_after_validation_failure_retries_remain(self):
        state = create_initial_state("Intent", max_retries=3)
        state["status"] = "validation_failed"
        state["validation_result"] = {"is_valid": False, "errors": [{"code": "IP_COLLISION"}]}
        state["retry_count"] = 1
        assert route_after_validation(state) == "topology_generation"

    def test_route_after_validation_failure_circuit_breaker(self):
        state = create_initial_state("Intent", max_retries=3)
        state["status"] = "validation_failed"
        state["validation_result"] = {"is_valid": False, "errors": [{"code": "IP_COLLISION"}]}
        state["retry_count"] = 3
        assert route_after_validation(state) == "circuit_breaker"

    # 2. Approval Edge
    def test_route_after_approval_approved(self):
        state = create_initial_state("Intent")
        state["human_approved"] = True
        assert route_after_approval(state) == "deployment"

    def test_route_after_approval_rejected(self):
        state = create_initial_state("Intent")
        state["human_approved"] = False
        assert route_after_approval(state) == "end"

    def test_route_after_approval_exhausted_retries_trips_breaker(self):
        state = create_initial_state("Intent", max_retries=2)
        state["human_approved"] = None
        state["retry_count"] = 2
        assert route_after_approval(state) == "circuit_breaker"

    # 3. Deployment Edge
    def test_route_after_deployment_success(self):
        state = create_initial_state("Intent")
        state["status"] = "deployed"
        state["deploy_status"] = {"success": True}
        assert route_after_deployment(state) == "verification_probing"

    def test_route_after_deployment_failure_retries_remain(self):
        state = create_initial_state("Intent", max_retries=3)
        state["status"] = "deployment_failed"
        state["deploy_status"] = {"success": False, "error_message": "Docker crash"}
        state["retry_count"] = 1
        assert route_after_deployment(state) == "diagnosis_and_healing"

    def test_route_after_deployment_failure_circuit_breaker(self):
        state = create_initial_state("Intent", max_retries=3)
        state["status"] = "deployment_failed"
        state["deploy_status"] = {"success": False, "error_message": "Docker crash"}
        state["retry_count"] = 3
        assert route_after_deployment(state) == "circuit_breaker"

    # 4. Verification Edge
    def test_route_after_verification_success(self):
        state = create_initial_state("Intent")
        state["status"] = "verified"
        state["verification_results"] = {"all_passed": True, "failures": []}
        assert route_after_verification(state) == "end"

    def test_route_after_verification_failure_retries_remain(self):
        state = create_initial_state("Intent", max_retries=3)
        state["status"] = "verification_failed"
        state["verification_results"] = {"all_passed": False, "failures": ["Ping loss 100%"]}
        state["retry_count"] = 2
        assert route_after_verification(state) == "diagnosis_and_healing"

    def test_route_after_verification_failure_circuit_breaker(self):
        state = create_initial_state("Intent", max_retries=3)
        state["status"] = "verification_failed"
        state["verification_results"] = {"all_passed": False, "failures": ["Ping loss 100%"]}
        state["retry_count"] = 3
        assert route_after_verification(state) == "circuit_breaker"
