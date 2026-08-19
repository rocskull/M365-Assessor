from m365_assessor.models.enums import CollectorStatus, CoverageStatus
from m365_assessor.permissions import PermissionAnalyzer, load_permission_matrix


def test_permission_detection_is_case_insensitive() -> None:
    analyzer = PermissionAnalyzer(load_permission_matrix())
    result = analyzer.permission_results({"organization.read.all"})["entra"][0]
    assert result.detected is True


def test_zero_permission_area_is_not_assessed() -> None:
    analyzer = PermissionAnalyzer(load_permission_matrix())
    forms = next(item for item in analyzer.coverage(set()) if item.area == "forms")
    assert forms.status is CoverageStatus.NOT_ASSESSED
    assert forms.coverage_percent == 0
    assert "Forms.Read.All" in forms.missing_permissions


def test_collector_error_overrides_permission_coverage() -> None:
    analyzer = PermissionAnalyzer(load_permission_matrix())
    coverage = analyzer.coverage({"Organization.Read.All"}, {"entra001": CollectorStatus.ERROR})
    entra = next(item for item in coverage if item.area == "entra")
    assert entra.status is CoverageStatus.ERROR
    assert any("collector" in reason.lower() for reason in entra.reasons)


def test_planned_area_without_permissions_is_zero_coverage() -> None:
    analyzer = PermissionAnalyzer(load_permission_matrix())
    fabric = next(
        item
        for item in analyzer.coverage(set(), {"fabric001": CollectorStatus.NOT_ASSESSED})
        if item.area == "fabric"
    )
    assert fabric.status is CoverageStatus.NOT_ASSESSED
    assert fabric.coverage_percent == 0
