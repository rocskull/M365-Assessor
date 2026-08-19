from m365_assessor.models.assessment import CollectorExecution
from m365_assessor.models.enums import AssessmentStatus, CollectorStatus, Severity
from m365_assessor.rules.engine import RuleEngine
from m365_assessor.rules.models import EvaluationSpec, RuleDefinition


def _rule() -> RuleDefinition:
    return RuleDefinition(
        check_id="TEST-001",
        title="Test deterministic rule",
        description="Test",
        category="Identity",
        service="Entra ID",
        severity=Severity.HIGH,
        rationale="Test rationale",
        remediation="Test remediation",
        required_permissions={"Policy.Read.All"},
        collector_dependencies=["test001"],
        evaluation=EvaluationSpec(type="equals", field="test001.policy.enabled", expected=True),
        evidence_fields=["test001.policy.enabled"],
    )


def test_rule_passes_deterministically() -> None:
    collector = CollectorExecution(
        collector_id="test001",
        name="Test",
        area="entra",
        status=CollectorStatus.SUCCESS,
        data={"policy": {"enabled": True}},
    )
    result = RuleEngine().evaluate([_rule()], {"test001": collector}, {"Policy.Read.All"})[0]
    assert result.status is AssessmentStatus.PASS


def test_rule_fails_deterministically() -> None:
    collector = CollectorExecution(
        collector_id="test001",
        name="Test",
        area="entra",
        status=CollectorStatus.SUCCESS,
        data={"policy": {"enabled": False}},
    )
    result = RuleEngine().evaluate([_rule()], {"test001": collector}, {"Policy.Read.All"})[0]
    assert result.status is AssessmentStatus.FAIL


def test_missing_permission_is_not_failure() -> None:
    result = RuleEngine().evaluate([_rule()], {}, set())[0]
    assert result.status is AssessmentStatus.NOT_ASSESSED
    assert "Missing permissions" in result.observation


def test_missing_evidence_is_not_assessed() -> None:
    collector = CollectorExecution(
        collector_id="test001",
        name="Test",
        area="entra",
        status=CollectorStatus.SUCCESS,
        data={},
    )
    result = RuleEngine().evaluate([_rule()], {"test001": collector}, {"Policy.Read.All"})[0]
    assert result.status is AssessmentStatus.NOT_ASSESSED
