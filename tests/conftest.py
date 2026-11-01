"""Shared fixtures: make scripts/ importable and discover rules + sample data."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

SIGMA_DIR = REPO_ROOT / "detections" / "sigma"
DATA_DIR = REPO_ROOT / "tests" / "data"

RULE_PATHS = sorted(SIGMA_DIR.rglob("*.yml"))


def rule_id(path: Path) -> str:
    return path.stem


def sample_dir(rule_path: Path) -> Path:
    """tests/data/<rule file stem>/{true_positive,benign}/*.json"""
    return DATA_DIR / rule_path.stem


def load_samples(rule_path: Path, kind: str) -> list[tuple[str, dict]]:
    files = sorted((sample_dir(rule_path) / kind).glob("*.json"))
    return [(f.name, json.loads(f.read_text(encoding="utf-8"))) for f in files]
