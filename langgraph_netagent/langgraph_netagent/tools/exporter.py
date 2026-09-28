"""Topology and Device Configuration Exporter Enforcing POSIX LF Standards."""

from __future__ import annotations
import os
from pathlib import Path
from typing import Dict, List, Optional, Union
import yaml

from langgraph_netagent.models.topology import (
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
)


class TopologyExporter:
    """Exports topology definitions and node configuration files to disk.
    
    Guarantees strict POSIX LF ('\\n') line endings and appropriate file permissions
    to ensure seamless execution inside Linux containers and WSL2 environments.
    """

    def __init__(self, default_topo_filename: str = "lab.clab.yml"):
        self.default_topo_filename = default_topo_filename

    def export(
        self,
        package: FullTopologyPackage,
        export_dir: Union[str, Path],
        overwrite: bool = True,
        topo_filename: Optional[str] = None,
    ) -> Dict[str, Path]:
        """Export a full topology package (YAML and node configs) to the target directory.
        
        Args:
            package: The FullTopologyPackage containing topology file and device configs.
            export_dir: Target directory on disk.
            overwrite: If False and files exist, raises FileExistsError.
            topo_filename: Custom filename for topology YAML (defaults to '{name}.clab.yml' or 'lab.clab.yml').
            
        Returns:
            Dictionary mapping relative file paths to their absolute exported Paths on disk.
        """
        base_dir = Path(export_dir).resolve()
        base_dir.mkdir(parents=True, exist_ok=True)
        written_files: Dict[str, Path] = {}

        # 1. Export topology YAML file
        filename = topo_filename or (
            f"{package.topology.name}.clab.yml" if package.topology.name else self.default_topo_filename
        )
        topo_target = base_dir / filename
        self.export_topology_only(topology=package.topology, target_file=topo_target, overwrite=overwrite)
        written_files[filename] = topo_target

        # 2. Export each device configuration file
        for cfg in package.configs:
            cfg_path = self.export_config_file(config=cfg, export_dir=base_dir, overwrite=overwrite)
            rel_key = str(Path(cfg.file_path)).replace("\\", "/")
            written_files[rel_key] = cfg_path

        return written_files

    def export_topology_only(
        self,
        topology: ContainerlabTopologyFile,
        target_file: Union[str, Path],
        overwrite: bool = True,
    ) -> Path:
        """Write Containerlab topology YAML strictly with POSIX LF newlines.
        
        Args:
            topology: ContainerlabTopologyFile instance.
            target_file: Destination file path.
            overwrite: Whether to overwrite existing file.
            
        Returns:
            Path to written topology file.
        """
        p = Path(target_file).resolve()
        if p.exists() and not overwrite:
            raise FileExistsError(f"Target topology file already exists: {p}")
        p.parent.mkdir(parents=True, exist_ok=True)

        yaml_content = topology.to_yaml()
        # Enforce LF endings in memory first
        normalized_content = yaml_content.replace("\r\n", "\n").replace("\r", "\n")
        if not normalized_content.endswith("\n"):
            normalized_content += "\n"

        with open(p, mode="w", newline="\n", encoding="utf-8") as f:
            f.write(normalized_content)

        # Set default file permissions 0644
        try:
            os.chmod(p, 0o644)
        except Exception:
            pass

        return p

    def export_config_file(
        self,
        config: DeviceConfigFile,
        export_dir: Union[str, Path],
        overwrite: bool = True,
    ) -> Path:
        """Write a single device configuration file with LF line endings and octal permissions.
        
        Args:
            config: DeviceConfigFile instance.
            export_dir: Base directory where config.file_path will be resolved.
            overwrite: Whether to overwrite existing file.
            
        Returns:
            Path to written config file.
        """
        base_dir = Path(export_dir).resolve()
        # Handle relative file path
        clean_rel = Path(config.file_path)
        dest_path = base_dir / clean_rel

        if dest_path.exists() and not overwrite:
            raise FileExistsError(f"Target config file already exists: {dest_path}")

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Enforce POSIX LF endings
        raw_content = config.content.replace("\r\n", "\n").replace("\r", "\n")
        if not raw_content.endswith("\n"):
            raw_content += "\n"

        with open(dest_path, mode="w", newline="\n", encoding="utf-8") as f:
            f.write(raw_content)

        # Apply permissions (e.g. 0755 for scripts, 0644 for configs)
        try:
            mode_oct = int(config.permissions, 8)
            os.chmod(dest_path, mode_oct)
        except Exception:
            pass

        return dest_path
