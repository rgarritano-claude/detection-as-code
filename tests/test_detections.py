"""Rule quality gates, applied to every Sigma rule under detections/sigma/.

For each rule:
  1. it parses cleanly with pySigma (no collected errors),
  2. it carries the metadata this repo requires (ATT&CK tags, level, FPs, refs),
  3. it converts to Splunk SPL, and the committed .spl matches a fresh conversion,
  4. it fires on every true-positive sample and on no benign sample.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaLevel, SigmaRule

from conftest import RULE_PATHS, load_samples, rule_id, sample_dir
from convert import convert_rule, output_path
from sigma_eval import rule_matches

pytestmark = pytest.mark.skipif(not RULE_PATHS, reason="no Sigma rules found")

ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def _load(rule_path: Path) -> SigmaRule:
    collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
    assert len(collection.rules) == 1, "one rule per file"
    return collection.rules[0]


@pytest.fixture(params=RULE_PATHS, ids=rule_id)
def rule_path(request) -> Path:
    return request.param


# --- 1. parsing ----------------------------------------------------------------


def test_rule_parses(rule_path: Path):
    rule = _load(rule_path)
    assert not rule.errors, f"pySigma reported errors: {rule.errors}"
    # Force condition parsing; raises on a bad condition expression.
    assert rule.detection.parsed_condition[0].parsed is not None


# --- 2. metadata ---------------------------------------------------------------


def test_rule_metadata(rule_path: Path):
    rule = _load(rule_path)
    assert rule.id, "rule must have a UUID id"
    assert rule.description and rule.description.strip()
    assert rule.level in {SigmaLevel.LOW, SigmaLevel.MEDIUM, SigmaLevel.HIGH, SigmaLevel.CRITICAL}
    assert rule.falsepositives, "document expected false positives"
    assert rule.references, "cite at least one reference"
    tags = [str(t) for t in rule.tags]
    assert any(ATTACK_TECHNIQUE.match(t) for t in tags), f"needs an ATT&CK technique tag, got {tags}"


def test_rule_ids_unique():
    ids = [str(_load(p).id) for p in RULE_PATHS]
    assert len(ids) == len(set(ids)), "duplicate rule ids"


# --- 3. conversion ---------------------------------------------------------------


def test_converts_to_spl(rule_path: Path):
    spl = convert_rule(rule_path)
    query_lines = [ln for ln in spl.splitlines() if ln and not ln.startswith("```")]
    assert query_lines, "conversion produced an empty query"
    # Every log source must have a pipeline in scripts/pipelines/ that scopes it.
    assert "sourcetype=" in spl, "no sourcetype scoping; add a pipeline for this logsource"


def test_committed_spl_is_current(rule_path: Path):
    out = output_path(rule_path)
    assert out.exists(), f"missing {out}; run `make convert`"
    assert out.read_text(encoding="utf-8") == convert_rule(rule_path), "stale SPL; run `make convert`"


# --- 4. matching logic -----------------------------------------------------------


def test_has_samples(rule_path: Path):
    assert load_samples(rule_path, "true_positive"), f"add TP samples under {sample_dir(rule_path)}"
    assert load_samples(rule_path, "benign"), f"add benign samples under {sample_dir(rule_path)}"


def test_samples_are_labeled_synthetic(rule_path: Path):
    for kind in ("true_positive", "benign"):
        for name, doc in load_samples(rule_path, kind):
            assert doc.get("_meta", {}).get("synthetic") is True, f"{name}: _meta.synthetic must be true"


def test_fires_on_true_positives(rule_path: Path):
    rule = _load(rule_path)
    for name, doc in load_samples(rule_path, "true_positive"):
        assert rule_matches(rule, doc["event"]), f"rule did NOT fire on TP sample {name}"


def test_quiet_on_benign(rule_path: Path):
    rule = _load(rule_path)
    for name, doc in load_samples(rule_path, "benign"):
        assert not rule_matches(rule, doc["event"]), f"rule fired on benign sample {name}"
