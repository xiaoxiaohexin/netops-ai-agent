import os
import pytest
from pathlib import Path

from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter
from langgraph_netagent.models.topology import (
    FullTopologyPackage,
    ContainerlabTopologyFile,
    ContainerlabTopologyDefinition,
    ContainerlabNodeConfig,
)

@pytest.fixture
def smoke_adapter():
    adapter = LiveContainerlabAdapter(lab_name="smoke_test_lab")
    # Check if clab is installed
    try:
        import subprocess
        subprocess.run(["clab", "version"], check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("Containerlab not installed or not in PATH. Skipping smoke test.")
    
    yield adapter
    
    # Teardown
    try:
        adapter.destroy(cleanup=True)
    except Exception as e:
        print(f"Teardown failed: {e}")

def test_live_clab_adapter_smoke(smoke_adapter):
    """Smoke test for LiveContainerlabAdapter deploy and exec."""
    # Build a tiny 1-node topology
    node = ContainerlabNodeConfig(kind="linux", image="alpine:latest")
    topo_def = ContainerlabTopologyDefinition(name="smoke_test_lab", nodes={"node1": node})
    topo_file = ContainerlabTopologyFile(topology=topo_def)
    
    import tempfile
    import yaml
    
    with tempfile.TemporaryDirectory() as tmpdir:
        topo_path = Path(tmpdir) / "smoke.clab.yml"
        
        # Write a minimal valid clab yaml
        clab_yaml = {
            "name": "smoke_test_lab",
            "topology": {
                "nodes": {
                    "node1": {"kind": "linux", "image": "alpine:latest"}
                }
            }
        }
        with open(topo_path, "w") as f:
            yaml.dump(clab_yaml, f)
            
        # 1. Deploy
        result = smoke_adapter.deploy(topo_path)
        # Note: LiveContainerlabAdapter.deploy returns a DeploymentResult, not a bool
        assert result.success is True, f"Deployment should succeed: {result.error}"
    
    # 2. Exec command
    # "ip a" should exist on alpine
    output = smoke_adapter.exec_command(node_name="node1", command="ip a")
    assert output is not None
    assert output.exit_code == 0
    assert "lo:" in output.stdout or "eth0:" in output.stdout, f"Unexpected output: {output.stdout}"
