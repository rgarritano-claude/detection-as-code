"""Structure gates applied to every playbook under soar/playbooks/<name>/."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from conftest import PLAYBOOK_DIRS, load_playbook

pytestmark = pytest.mark.skipif(not PLAYBOOK_DIRS, reason="no playbooks found")


@pytest.fixture(params=PLAYBOOK_DIRS, ids=lambda p: p.name)
def playbook_dir(request) -> Path:
    return request.param


def test_layout(playbook_dir: Path):
    assert (playbook_dir / f"{playbook_dir.name}.py").is_file(), "playbook file must be <dir>/<dir>.py"
    readme = playbook_dir / "README.md"
    assert readme.is_file(), "playbook needs a README.md"
    text = readme.read_text(encoding="utf-8")
    assert "```mermaid" in text, "README needs a Mermaid flow diagram"
    assert "lab simulation" in text.lower(), "README must state it is built/tested as a lab simulation"


def test_parses_as_python_39(playbook_dir: Path):
    """Keep playbooks to Python 3.9 syntax for SOAR runtime compatibility (rejects e.g. match)."""
    source = (playbook_dir / f"{playbook_dir.name}.py").read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 9))


def test_entry_points(playbook_dir: Path):
    module = load_playbook(playbook_dir)
    assert callable(getattr(module, "on_start", None)), "missing on_start(container)"
    assert callable(getattr(module, "on_finish", None)), "missing on_finish(container, summary)"


def test_no_hardcoded_secrets(playbook_dir: Path):
    source = (playbook_dir / f"{playbook_dir.name}.py").read_text(encoding="utf-8").lower()
    for marker in ("api_key=", "apikey", "password=", "secret=", "bearer "):
        assert marker not in source, f"possible hard-coded credential marker: {marker!r}"
