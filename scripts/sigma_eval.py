"""Minimal in-memory Sigma evaluator for unit-testing rules against JSON events.

pySigma parses and converts rules but does not evaluate them against data.
This module walks pySigma's parsed condition tree and applies it to a Python
dict (e.g. a CloudTrail record), so tests can assert that a rule fires on
true-positive samples and stays quiet on benign ones without a SIEM.

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
    """Resolve a dotted field path (``userIdentity.userName``) in nested dicts."""
    node: Any = event
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


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


def _present(value: Any) -> bool:
    return value is not _MISSING and value is not None


def _match_value(actual: Any, expected: Any, event: dict[str, Any]) -> bool:
    if isinstance(expected, SigmaExists):
        return _present(actual) == expected.exists
    if isinstance(expected, SigmaNull):
        return not _present(actual) or actual == ""
    if not _present(actual):
        return False
    if isinstance(expected, SigmaFieldReference):
        other = get_field(event, expected.field)
        return _present(other) and str(actual).lower() == str(other).lower()
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


def _evaluate(node: Any, event: dict[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_evaluate(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _evaluate(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(get_field(event, node.field), node.value, event)
    raise NotImplementedError(f"Unsupported condition node: {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """True if any of the rule's conditions match the event."""
    return any(_evaluate(cond.parsed, event) for cond in rule.detection.parsed_condition)
