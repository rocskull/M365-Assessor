from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from m365_assessor.models.assessment import CollectorExecution
from m365_assessor.models.enums import AssessmentStatus, CollectorStatus
from m365_assessor.rules.engine import RuleEngine
from m365_assessor.rules.loader import default_rule_registry
from m365_assessor.rules.models import EvaluationSpec, RuleDefinition


def _set(document: dict[str, Any], path: str, value: Any) -> None:
    current = document
    parts = path.split(".")
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value


def _value_for(spec: EvaluationSpec, passing: bool) -> Any:
    if spec.type in {"equals", "equals_ci"}:
        if passing:
            return spec.expected
        if isinstance(spec.expected, bool):
            return not spec.expected
        if isinstance(spec.expected, int):
            return spec.expected + 1
        if isinstance(spec.expected, list):
            return ["different"]
        return f"not-{spec.expected}"
    if spec.type in {"in", "in_ci"}:
        return spec.expected[0] if passing else "not-listed"
    if spec.type == "truthy":
        return ["configured"] if passing else []
    if spec.type == "falsy":
        return None if passing else "configured"
    if spec.type == "contains":
        return [spec.expected] if passing else ["different"]
    if spec.type == "not_contains":
        return ["different"] if passing else [spec.expected]
    if spec.type == "lte":
        return spec.expected if passing else spec.expected + 1
    if spec.type == "gte":
        return spec.expected if passing else spec.expected - 1
    if spec.type == "between":
        return spec.expected[0] if passing else spec.expected[1] + 1
    raise AssertionError(f"Unsupported leaf in test builder: {spec.type}")


def _apply(spec: EvaluationSpec, document: dict[str, Any], passing: bool) -> None:
    if spec.type == "all":
        for index, condition in enumerate(spec.conditions):
            _apply(condition, document, passing or index > 0)
        return
    if spec.type == "any":
        for index, condition in enumerate(spec.conditions):
            _apply(condition, document, passing and index == 0)
        return
    if spec.type == "collection":
        if passing and spec.quantifier == "none":
            _set(document, spec.field, [])
            return
        if not passing and spec.quantifier == "any":
            _set(document, spec.field, [])
            return
        item: dict[str, Any] = {}
        for index, condition in enumerate(spec.conditions):
            condition_passes = passing or spec.quantifier == "none" or index > 0
            _apply(condition, item, condition_passes)
        _set(document, spec.field, [item])
        return
    _set(document, spec.field, _value_for(spec, passing))


def _executions(evidence: dict[str, Any], rule: RuleDefinition) -> dict[str, CollectorExecution]:
    return {
        collector_id: CollectorExecution(
            collector_id=collector_id,
            name=collector_id,
            area="service",
            status=CollectorStatus.SUCCESS,
            data=evidence.get(collector_id, {}),
        )
        for collector_id in rule.collector_dependencies
    }


SERVICE_RULES = [
    rule for rule in default_rule_registry().all() if not rule.check_id.startswith("M365-ENTRA-")
]


@pytest.mark.parametrize("rule", SERVICE_RULES, ids=lambda item: item.check_id)
def test_each_service_rule_has_deterministic_pass_and_fail(rule: RuleDefinition) -> None:
    passing: dict[str, Any] = {}
    _apply(rule.evaluation, passing, True)
    passed = RuleEngine().evaluate([rule], _executions(passing, rule), set())[0]
    assert passed.status is AssessmentStatus.PASS
    assert passed.remediation
    assert {item.framework for item in passed.benchmark} == {"CIS", "NIST"}

    failing = deepcopy(passing)
    _apply(rule.evaluation, failing, False)
    failed = RuleEngine().evaluate([rule], _executions(failing, rule), set())[0]
    assert failed.status is AssessmentStatus.FAIL


def test_service_rule_pack_count_and_unique_ids() -> None:
    assert len(SERVICE_RULES) == 73
    assert len({item.check_id for item in SERVICE_RULES}) == len(SERVICE_RULES)
