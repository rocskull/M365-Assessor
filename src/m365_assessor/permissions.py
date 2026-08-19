from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from m365_assessor.models.assessment import CoverageArea, PermissionResult
from m365_assessor.models.enums import AssessmentStatus, CollectorStatus, CoverageStatus, Severity


class PermissionEntry(BaseModel):
    permission: str
    required_by_collectors: list[str] = Field(default_factory=list)
    affected_checks: list[str] = Field(default_factory=list)
    limitation_severity: Severity = Severity.MEDIUM
    detection: Literal["token", "collector"] = "token"


class PermissionArea(BaseModel):
    name: str
    collectors: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    permissions: list[PermissionEntry]


class PermissionMatrix(BaseModel):
    version: str
    areas: dict[str, PermissionArea]


def _default_matrix_text() -> str:
    project_path = Path(__file__).resolve().parents[2] / "config" / "permissions.yaml"
    if project_path.exists():
        return project_path.read_text(encoding="utf-8")
    return files("m365_assessor").joinpath("data/permissions.yaml").read_text(encoding="utf-8")


def load_permission_matrix(path: Path | None = None) -> PermissionMatrix:
    raw = path.read_text(encoding="utf-8") if path else _default_matrix_text()
    payload: Any = yaml.safe_load(raw)
    if not isinstance(payload, dict):
        raise ValueError("permission matrix must be a YAML mapping")
    return PermissionMatrix.model_validate(payload)


class PermissionAnalyzer:
    def __init__(self, matrix: PermissionMatrix) -> None:
        self.matrix = matrix

    def permission_results(
        self,
        detected: set[str],
        collector_statuses: dict[str, CollectorStatus] | None = None,
    ) -> dict[str, list[PermissionResult]]:
        normalized = {item.casefold() for item in detected}
        collector_statuses = collector_statuses or {}
        output: dict[str, list[PermissionResult]] = {}
        for area_id, area in self.matrix.areas.items():
            output[area_id] = []
            for entry in area.permissions:
                if entry.detection == "collector":
                    relevant = [
                        collector_statuses[item]
                        for item in entry.required_by_collectors
                        if item in collector_statuses
                    ]
                    is_detected = any(
                        item in {CollectorStatus.SUCCESS, CollectorStatus.PARTIAL}
                        for item in relevant
                    )
                    reason = (
                        None
                        if is_detected
                        else "Service authorization is verified by the collector at runtime."
                    )
                else:
                    is_detected = entry.permission.casefold() in normalized
                    reason = (
                        None
                        if is_detected
                        else f"{entry.permission} was not detected in the current token grant."
                    )
                output[area_id].append(
                    PermissionResult(
                        permission=entry.permission,
                        detected=is_detected,
                        required_by_collectors=entry.required_by_collectors,
                        affected_checks=entry.affected_checks,
                        limitation_severity=entry.limitation_severity,
                        reason=reason,
                        verification_source=entry.detection,
                    )
                )
        return output

    def coverage(
        self,
        detected: set[str],
        collector_statuses: dict[str, CollectorStatus] | None = None,
        check_statuses: dict[str, AssessmentStatus] | None = None,
    ) -> list[CoverageArea]:
        collector_statuses = collector_statuses or {}
        check_statuses = check_statuses or {}
        results = self.permission_results(detected, collector_statuses)
        coverage: list[CoverageArea] = []
        for area_id, permissions in results.items():
            area = self.matrix.areas[area_id]
            required = [item.permission for item in permissions]
            present = [item.permission for item in permissions if item.detected]
            missing = [item.permission for item in permissions if not item.detected]
            percent = round(100 * len(present) / len(required), 2) if required else 100.0
            affected_collectors = sorted(
                set(area.collectors)
                | {collector for item in permissions for collector in item.required_by_collectors}
            )
            affected_checks = sorted(
                set(area.checks) | {check for item in permissions for check in item.affected_checks}
            )
            reasons = [item.reason for item in permissions if item.reason]
            statuses = {
                collector_statuses[item]
                for item in affected_collectors
                if item in collector_statuses
            }
            evaluated_checks = [
                check_statuses[item] for item in affected_checks if item in check_statuses
            ]
            if evaluated_checks:
                assessed = sum(
                    item
                    in {
                        AssessmentStatus.PASS,
                        AssessmentStatus.FAIL,
                        AssessmentStatus.WARNING,
                        AssessmentStatus.NOT_APPLICABLE,
                    }
                    for item in evaluated_checks
                )
                percent = round(100 * assessed / len(evaluated_checks), 2)
            if statuses and statuses <= {CollectorStatus.ERROR}:
                status = CoverageStatus.ERROR
                percent = 0.0
                reasons.append("Every executed collector in this area returned an error.")
            elif statuses == {CollectorStatus.NOT_ASSESSED}:
                status = CoverageStatus.NOT_ASSESSED
                percent = 0.0
                reasons.append("No collector in this area could be assessed.")
            elif statuses & {
                CollectorStatus.NOT_ASSESSED,
                CollectorStatus.PARTIAL,
                CollectorStatus.ERROR,
            }:
                status = CoverageStatus.PARTIAL
                reasons.append("At least one collector in this area was partial or unavailable.")
            elif affected_collectors and not statuses:
                status = CoverageStatus.NOT_ASSESSED
                percent = 0.0
                reasons.append("No collector execution was available in the selected scope.")
            elif percent >= 90:
                status = CoverageStatus.ASSESSED
            elif percent > 0:
                status = CoverageStatus.PARTIAL
            else:
                status = CoverageStatus.NOT_ASSESSED
            coverage.append(
                CoverageArea(
                    area=area_id,
                    name=area.name,
                    status=status,
                    coverage_percent=percent,
                    reasons=reasons,
                    required_permissions=required,
                    detected_permissions=present,
                    missing_permissions=missing,
                    affected_collectors=affected_collectors,
                    affected_checks=affected_checks,
                )
            )
        return coverage
