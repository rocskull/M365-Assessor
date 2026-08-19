from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from m365_assessor.models.assessment import CheckResult, CollectorExecution
from m365_assessor.models.enums import AssessmentStatus, CollectorStatus
from m365_assessor.rules.models import EvaluationSpec, RuleDefinition

_MISSING = object()


def _resolve(document: dict[str, Any], dotted_path: str) -> Any:
    current: Any = document
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _evaluate(spec: EvaluationSpec, evidence: dict[str, Any]) -> bool:
    if spec.type == "all":
        if not spec.conditions:
            raise ValueError("all requires at least one nested condition")
        return all(_evaluate(condition, evidence) for condition in spec.conditions)
    if spec.type == "any":
        if not spec.conditions:
            raise ValueError("any requires at least one nested condition")
        return any(_evaluate(condition, evidence) for condition in spec.conditions)
    if spec.type == "not":
        if len(spec.conditions) != 1:
            raise ValueError("not requires exactly one nested condition")
        return not _evaluate(spec.conditions[0], evidence)
    if spec.type == "restriction_set":
        return _evaluate_restrictions(spec, evidence)
    value = _resolve(evidence, spec.field)
    if spec.type == "exists":
        return value is not _MISSING and value is not None
    if value is _MISSING:
        raise KeyError(spec.field)
    if spec.type == "collection":
        if not isinstance(value, list):
            raise TypeError("collection requires a list field")
        if len(value) < spec.min_count:
            return False
        matches = [
            all(
                _evaluate(condition, item if isinstance(item, dict) else {"value": item})
                for condition in spec.conditions
            )
            for item in value
        ]
        if spec.quantifier == "all":
            return all(matches)
        if spec.quantifier == "any":
            return any(matches)
        return not any(matches)
    if spec.type == "equals":
        return bool(value == spec.expected)
    if spec.type == "equals_ci":
        return str(value).casefold() == str(spec.expected).casefold()
    if spec.type == "not_equals":
        return bool(value != spec.expected)
    if spec.type == "count_gte":
        if not isinstance(value, (list, dict, str)) or not isinstance(spec.expected, int):
            raise TypeError("count_gte requires a countable value and integer expected value")
        return len(value) >= spec.expected
    if spec.type == "in":
        if not isinstance(spec.expected, list):
            raise TypeError("in requires a list expected value")
        return value in spec.expected
    if spec.type == "in_ci":
        if not isinstance(spec.expected, list):
            raise TypeError("in_ci requires a list expected value")
        return str(value).casefold() in {str(item).casefold() for item in spec.expected}
    if spec.type == "contains":
        if not isinstance(value, (list, str)):
            raise TypeError("contains requires a list or string value")
        return spec.expected in value
    if spec.type == "not_contains":
        if not isinstance(value, (list, str)):
            raise TypeError("not_contains requires a list or string value")
        return spec.expected not in value
    if spec.type == "truthy":
        return bool(value)
    if spec.type == "falsy":
        return not bool(value)
    if spec.type == "lte":
        return bool(value <= spec.expected)
    if spec.type == "gte":
        return bool(value >= spec.expected)
    if spec.type == "between":
        if not isinstance(spec.expected, list) or len(spec.expected) != 2:
            raise TypeError("between requires [minimum, maximum]")
        return bool(spec.expected[0] <= value <= spec.expected[1])
    raise ValueError(f"Unsupported evaluation type: {spec.type}")


_DURATION = re.compile(
    r"^P(?:(?P<days>\d+(?:\.\d+)?)D)?(?:T(?:(?P<hours>\d+(?:\.\d+)?)H)?"
    r"(?:(?P<minutes>\d+(?:\.\d+)?)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$"
)


def _duration_days(value: str) -> float:
    match = _DURATION.fullmatch(value)
    if match is None:
        raise ValueError("invalid ISO 8601 day/time duration")
    days = float(match.group("days") or 0)
    hours = float(match.group("hours") or 0)
    minutes = float(match.group("minutes") or 0)
    seconds = float(match.group("seconds") or 0)
    return days + hours / 24 + minutes / 1440 + seconds / 86400


def _effective_now(value: object) -> bool:
    if value is None or value in ("", "0001-01-01T00:00:00Z"):
        return True
    if not isinstance(value, str):
        return False
    try:
        effective = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return effective <= datetime.now(UTC)


def _evaluate_restrictions(spec: EvaluationSpec, evidence: dict[str, Any]) -> bool:
    if not spec.fields:
        raise ValueError("restriction_set requires fields")
    options = spec.expected if isinstance(spec.expected, dict) else {}
    max_days = options.get("max_days")
    for field in spec.fields:
        restriction = _resolve(evidence, field)
        if not isinstance(restriction, dict) or restriction.get("state") != "enabled":
            return False
        if not _effective_now(restriction.get("restrictForAppsCreatedAfterDateTime")):
            return False
        if max_days is not None:
            lifetime = restriction.get("maxLifetime")
            if not isinstance(lifetime, str) or _duration_days(lifetime) > float(max_days):
                return False
    return True


class RuleEngine:
    def evaluate(
        self,
        rules: list[RuleDefinition],
        collectors: dict[str, CollectorExecution],
        granted_permissions: set[str],
    ) -> list[CheckResult]:
        return [self._evaluate_rule(rule, collectors, granted_permissions) for rule in rules]

    def _evaluate_rule(
        self,
        rule: RuleDefinition,
        collectors: dict[str, CollectorExecution],
        granted_permissions: set[str],
    ) -> CheckResult:
        normalized = {item.casefold() for item in granted_permissions}
        missing_permissions = sorted(
            item for item in rule.required_permissions if item.casefold() not in normalized
        )
        missing_collectors = [
            item for item in rule.collector_dependencies if item not in collectors
        ]
        unavailable_collectors = [
            item
            for item in rule.collector_dependencies
            if item in collectors
            and collectors[item].status not in {CollectorStatus.SUCCESS, CollectorStatus.PARTIAL}
        ]
        evidence = {
            collector_id: collectors[collector_id].data
            for collector_id in rule.collector_dependencies
            if collector_id in collectors
        }
        if missing_permissions or missing_collectors or unavailable_collectors:
            reasons = []
            if missing_permissions:
                reasons.append(f"Missing permissions: {', '.join(missing_permissions)}")
            if missing_collectors:
                reasons.append(f"Missing collectors: {', '.join(missing_collectors)}")
            if unavailable_collectors:
                reasons.append(f"Unavailable collectors: {', '.join(unavailable_collectors)}")
            return self._result(rule, AssessmentStatus.NOT_ASSESSED, evidence, "; ".join(reasons))
        try:
            passed = _evaluate(rule.evaluation, evidence)
            status = AssessmentStatus.PASS if passed else AssessmentStatus.FAIL
            observation = (
                "Evaluation condition was satisfied."
                if passed
                else "Evaluation condition was not satisfied."
            )
            return self._result(rule, status, evidence, observation)
        except KeyError as exc:
            return self._result(
                rule,
                AssessmentStatus.NOT_ASSESSED,
                evidence,
                f"Required evidence field was unavailable: {exc.args[0]}",
            )
        except Exception as exc:
            return self._result(
                rule,
                AssessmentStatus.ERROR,
                evidence,
                f"Evaluation error: {type(exc).__name__}",
            )

    @staticmethod
    def _result(
        rule: RuleDefinition,
        status: AssessmentStatus,
        evidence: dict[str, Any],
        observation: str,
    ) -> CheckResult:
        return CheckResult(
            check_id=rule.check_id,
            title=rule.title,
            severity=rule.severity,
            status=status,
            service=rule.service,
            category=rule.category,
            description=rule.description,
            rationale=rule.rationale,
            business_impact=rule.business_impact,
            benchmark=rule.benchmarks,
            evidence=evidence,
            observation=observation,
            recommendation=rule.recommendation,
            remediation=rule.remediation,
            references=rule.references,
        )
