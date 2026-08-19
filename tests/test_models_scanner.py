from __future__ import annotations

import httpx
import pytest

from m365_assessor.config import Settings
from m365_assessor.core.scanner import Scanner, build_dry_run
from m365_assessor.models.assessment import AssessmentSummary, CheckResult
from m365_assessor.models.enums import AssessmentStatus, Severity


def _result(status: AssessmentStatus) -> CheckResult:
    return CheckResult(
        check_id=f"TEST-{status}",
        title="Test",
        severity=Severity.HIGH,
        status=status,
        service="Test",
        category="Test",
    )


def test_pass_percentage_excludes_not_assessed() -> None:
    summary = AssessmentSummary.from_results(
        [
            _result(AssessmentStatus.PASS),
            _result(AssessmentStatus.FAIL),
            _result(AssessmentStatus.NOT_ASSESSED),
        ]
    )
    assert summary.pass_percentage == 50
    assert summary.coverage_percentage == pytest.approx(66.67)


def test_dry_run_lists_frameworks_and_permissions() -> None:
    plan = build_dry_run(Settings(tenant_id="tenant"), ["nist-csf-2.0"], area="entra")
    assert plan.frameworks == ["nist-csf-2.0"]
    assert plan.collectors[0].id == "entra001"
    assert "Organization.Read.All" in plan.required_permissions
    assert len(plan.checks) == 24


@pytest.mark.asyncio
async def test_scanner_builds_normalized_document(graph_factory, auth_result) -> None:
    graph = graph_factory(
        httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "tenant-id",
                            "displayName": "Contoso",
                            "verifiedDomains": [{"name": "contoso.example", "isDefault": True}],
                        }
                    ]
                },
            )
        )
    )
    document = await Scanner(Settings()).scan(
        ["cis-m365-7.0.0", "nist-csf-2.0"],
        area="entra",
        auth_result=auth_result,
        graph_client=graph,
    )
    assert document.tenant.display_name == "Contoso"
    assert document.tenant.primary_domain == "contoso.example"
    assert len(document.assessment.frameworks) == 2
    assert "entra001" in document.collectors
    assert len(document.checks) == 24
    assert all(item.status is AssessmentStatus.NOT_ASSESSED for item in document.checks)
    assert all(
        {mapping.framework for mapping in item.benchmark} == {"CIS", "NIST"}
        for item in document.checks
    )


def test_dry_run_excludes_checks_outside_selected_area() -> None:
    plan = build_dry_run(Settings(tenant_id="tenant"), ["cis-m365-7.0.0"], area="exchange")
    assert len(plan.checks) == 28
    assert all(item.startswith("M365-EXO-") for item in plan.checks)
    assert "User.Read.All" not in plan.required_permissions
