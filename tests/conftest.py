"""Shared fixtures: import paths, plus discovery of rules, playbooks, and sample data."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
# Offline mock of the Splunk SOAR `phantom` package, so playbooks import in tests.
sys.path.insert(0, str(REPO_ROOT / "tests" / "mocks"))

SIGMA_DIR = REPO_ROOT / "detections" / "sigma"
DATA_DIR = REPO_ROOT / "tests" / "data"
PLAYBOOK_DIR = REPO_ROOT / "soar" / "playbooks"

RULE_PATHS = sorted(SIGMA_DIR.rglob("*.yml"))
PLAYBOOK_DIRS = sorted(p for p in PLAYBOOK_DIR.iterdir() if p.is_dir())


def rule_id(path: Path) -> str:
    return path.stem


def sample_dir(rule_path: Path) -> Path:
    """tests/data/<rule file stem>/{true_positive,benign}/*.json"""
    return DATA_DIR / rule_path.stem


def load_samples(rule_path: Path, kind: str) -> list[tuple[str, dict]]:
    files = sorted((sample_dir(rule_path) / kind).glob("*.json"))
    return [(f.name, json.loads(f.read_text(encoding="utf-8"))) for f in files]


def load_playbook(playbook_dir: Path):
    """Import soar/playbooks/<name>/<name>.py as a fresh module (uses the phantom mock)."""
    import importlib.util

    path = playbook_dir / f"{playbook_dir.name}.py"
    spec = importlib.util.spec_from_file_location(f"playbook_{playbook_dir.name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
