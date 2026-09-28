"""Unit tests for TopologyExporter and strict POSIX LF newline enforcement."""

import os
from pathlib import Path
import pytest

from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
)
from langgraph_netagent.tools.exporter import TopologyExporter


class TestTopologyExporter:
    """Test suite for TopologyExporter disk serialization."""

    def test_export_full_package_creates_hierarchy(
        self,
        tmp_path: Path,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        exporter = TopologyExporter()
        written = exporter.export(package=full_multi_node_package, export_dir=tmp_path)

        assert len(written) == 5  # 1 topology + 4 device configs
        assert (tmp_path / "multi-vendor-lab.clab.yml").exists()
        assert (tmp_path / "config" / "pc1" / "setup.sh").exists()
        assert (tmp_path / "config" / "frr" / "frr.conf").exists()
        assert (tmp_path / "config" / "srl" / "srl.cfg").exists()
        assert (tmp_path / "config" / "pc2" / "setup.sh").exists()

    def test_strict_posix_lf_line_endings_no_carriage_returns(
        self,
        tmp_path: Path,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        # Deliberately inject CRLF (\r\n) into one of the config contents
        full_multi_node_package.configs[0].content = "#!/bin/sh\r\necho hello\r\nip link up\r\n"

        exporter = TopologyExporter()
        written = exporter.export(package=full_multi_node_package, export_dir=tmp_path)

        # Inspect EVERY exported file in raw binary mode
        for rel_path, abs_path in written.items():
            assert abs_path.is_file()
            raw_bytes = abs_path.read_bytes()
            assert b"\r" not in raw_bytes, f"Carriage return (\\r) detected in exported file: {rel_path}"
            assert raw_bytes.endswith(b"\n"), f"File does not terminate with trailing LF: {rel_path}"

    def test_export_preserves_content_integrity(
        self,
        tmp_path: Path,
    ) -> None:
        cfg = DeviceConfigFile(
            node_name="test-node",
            file_path="config/test/test.conf",
            content="line 1\nline 2\nline 3\n",
            permissions="0644",
        )
        exporter = TopologyExporter()
        dest = exporter.export_config_file(config=cfg, export_dir=tmp_path)

        text = dest.read_text(encoding="utf-8")
        assert text == "line 1\nline 2\nline 3\n"

    def test_overwrite_false_raises_error_when_file_exists(
        self,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ) -> None:
        exporter = TopologyExporter()
        exporter.export(package=sample_topology_package, export_dir=tmp_path)

        # Second export with overwrite=False must raise
        with pytest.raises(FileExistsError):
            exporter.export(package=sample_topology_package, export_dir=tmp_path, overwrite=False)

    def test_export_topology_only(
        self,
        tmp_path: Path,
        sample_topology_file: ContainerlabTopologyFile,
    ) -> None:
        exporter = TopologyExporter()
        target = tmp_path / "custom_lab.clab.yml"
        out_p = exporter.export_topology_only(topology=sample_topology_file, target_file=target)

        assert out_p.exists()
        raw = out_p.read_bytes()
        assert b"\r" not in raw
        assert b"test-lab" in raw
        assert b"mgmt:" in raw
