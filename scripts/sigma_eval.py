"""Minimal in-memory Sigma evaluator for unit-testing rules against JSON events.

pySigma parses and converts rules but does not evaluate them against data.
This module walks pySigma's parsed condition tree and applies it to a Python
dict (e.g. a CloudTrail record), so tests can assert that a rule fires on
true-positive samples and stays quiet on benign ones without a SIEM.

List traversal: when a path crosses a JSON array (e.g. Kubernetes
``requestObject.subjects.name``), every element is visited and the field matches
if **any** value matches, mirroring Splunk multivalue-field semantics.

Supported: AND / OR / NOT, plain and wildcard strings (case-insensitive),
``|contains`` / ``|startswith`` / ``|endswith``, ``|re``, ``|exists``,
``|fieldref``, ``null``, numbers and booleans. Anything else raises
``NotImplementedError`` so a test fails loudly instead of silently passing.
"""

from __future__ import annotations

import re
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaExists,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

_MISSING = object()


def get_field(event: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted field path (``userIdentity.userName``) in nested dicts.

    Returns the single value, or ``_MISSING``. Use ``get_values`` for paths that
    cross arrays.
    """
    node: Any = event
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def get_values(event: dict[str, Any], dotted: str) -> list[Any]:
    """All leaf values at a dotted path, descending into (and flattening) arrays."""

    def walk(node: Any, parts: list[str]) -> list[Any]:
        if isinstance(node, list):
            return [v for item in node for v in walk(item, parts)]
        if not parts:
            return [node]
        if isinstance(node, dict) and parts[0] in node:
            return walk(node[parts[0]], parts[1:])
        return []

    return walk(event, dotted.split("."))


def _present(value: Any) -> bool:
    return value is not _MISSING and value is not None


def _sigma_string_to_regex(value: SigmaString) -> str:
    parts = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(re.escape(part))
        elif part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            raise NotImplementedError(f"Unsupported Sigma string part: {part!r}")
    return "".join(parts)


def _match_scalar(actual: Any, expected: Any) -> bool:
    if isinstance(expected, SigmaString):
        regex = _sigma_string_to_regex(expected)
        return re.fullmatch(regex, str(actual), re.IGNORECASE | re.DOTALL) is not None
    if isinstance(expected, SigmaRegularExpression):
        return re.search(str(expected.regexp), str(actual)) is not None
    if isinstance(expected, SigmaNumber):
        try:
            return float(actual) == float(expected.number)
        except (TypeError, ValueError):
            return False
    if isinstance(expected, SigmaBool):
        return actual is expected.boolean or str(actual).lower() == str(expected.boolean).lower()
    raise NotImplementedError(f"Unsupported Sigma value type: {type(expected).__name__}")


def _match_value(field: str, expected: Any, event: dict[str, Any]) -> bool:
    present = [v for v in get_values(event, field) if _present(v)]
    if isinstance(expected, SigmaExists):
        return bool(present) == expected.exists
    if isinstance(expected, SigmaNull):
        return all(v == "" for v in present)
    if isinstance(expected, SigmaFieldReference):
        others = {str(v).lower() for v in get_values(event, expected.field) if _present(v)}
        return any(str(v).lower() in others for v in present)
    return any(_match_scalar(v, expected) for v in present)


def _evaluate(node: Any, event: dict[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _evaluate(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(node.field, node.value, event)
    raise NotImplementedError(f"Unsupported condition node: {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """True if any of the rule's conditions match the event."""
    return any(_evaluate(cond.parsed, event) for cond in rule.detection.parsed_condition)
