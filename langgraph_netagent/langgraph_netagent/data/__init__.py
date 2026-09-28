"""Training datasets and fine-tuning specifications for LangGraph NetAgent."""

from pathlib import Path
import json
from typing import Any, Dict, List

DATA_DIR = Path(__file__).resolve().parent
SFT_SAMPLES_PATH = DATA_DIR / "sft_samples.jsonl"


def load_sft_samples() -> List[Dict[str, Any]]:
    """Load and parse SFT JSONL training samples."""
    samples = []
    if SFT_SAMPLES_PATH.exists():
        with open(SFT_SAMPLES_PATH, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    samples.append(json.loads(stripped))
    return samples


__all__ = ["DATA_DIR", "SFT_SAMPLES_PATH", "load_sft_samples"]
