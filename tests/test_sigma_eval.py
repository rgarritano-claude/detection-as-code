"""Unit tests for the in-memory evaluator itself, so rule tests can trust it."""

from __future__ import annotations

import pytest
from sigma.rule import SigmaRule

from sigma_eval import get_field, rule_matches


def _rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(
        "title: t\nlogsource:\n  product: test\ndetection:\n" + detection
    )


def test_get_field_nested():
    assert get_field({"a": {"b": 1}}, "a.b") == 1


def test_wildcards_and_case_insensitive():
    r = _rule("  sel:\n    name|startswith: Create\n  condition: sel\n")
    assert rule_matches(r, {"name": "createAccessKey"})
    assert not rule_matches(r, {"name": "DeleteAccessKey"})


def test_exists_and_null():
    r = _rule("  sel:\n    a|exists: true\n  f:\n    b: null\n  condition: sel and f\n")
    assert rule_matches(r, {"a": 1})
    assert rule_matches(r, {"a": 1, "b": None})
    assert not rule_matches(r, {"a": 1, "b": "x"})
    assert not rule_matches(r, {"b": None})


def test_fieldref():
    r = _rule("  sel:\n    a|fieldref: b\n  condition: sel\n")
    assert rule_matches(r, {"a": "x", "b": "X"})
    assert not rule_matches(r, {"a": "x", "b": "y"})
    assert not rule_matches(r, {"a": "x"})


def test_unsupported_raises():
    r = _rule("  keywords:\n    - foo\n  condition: keywords\n")
    with pytest.raises(NotImplementedError):
        rule_matches(r, {"x": "foo"})


def test_regex():
    r = _rule("  sel:\n    a|re: '^ab\\.c$'\n  condition: sel\n")
    assert rule_matches(r, {"a": "ab.c"})
    assert not rule_matches(r, {"a": "abxc"})


def test_list_traversal_any_semantics():
    r = _rule("  sel:\n    subjects.name|startswith: 'system:'\n  condition: sel\n")
    assert rule_matches(r, {"subjects": [{"name": "lab-user"}, {"name": "system:masters"}]})
    assert not rule_matches(r, {"subjects": [{"name": "lab-user"}]})


def test_list_traversal_exists_and_bool():
    r = _rule("  sel:\n    spec.containers.securityContext.privileged: true\n"
              "  hp:\n    spec.volumes.hostPath.path|exists: true\n  condition: sel or hp\n")
    assert rule_matches(r, {"spec": {"containers": [{"name": "a"}, {"securityContext": {"privileged": True}}]}})
    assert rule_matches(r, {"spec": {"volumes": [{"emptyDir": {}}, {"hostPath": {"path": "/"}}]}})
    assert not rule_matches(r, {"spec": {"containers": [{"securityContext": {"privileged": False}}],
                                         "volumes": [{"emptyDir": {}}]}})


def test_numbers():
    r = _rule("  sel:\n    code:\n      - 200\n      - 201\n  condition: sel\n")
    assert rule_matches(r, {"code": 201})
    assert not rule_matches(r, {"code": 403})
