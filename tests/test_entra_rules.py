from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from m365_assessor.models.assessment import CollectorExecution
from m365_assessor.models.enums import AssessmentStatus, CollectorStatus
from m365_assessor.rules.engine import RuleEngine
from m365_assessor.rules.loader import default_rule_registry


def _restriction(max_lifetime: str | None = None) -> dict[str, object]:
    return {
        "state": "enabled",
        "maxLifetime": max_lifetime,
        "restrictForAppsCreatedAfterDateTime": "0001-01-01T00:00:00Z",
    }


def _passing_evidence() -> dict[str, dict[str, Any]]:
    password_add = _restriction()
    lifetime = _restriction("P180D")
    return {
        "entra002": {
            "synced_privileged_user_count": 0,
            "synced_privileged_users": [],
            "global_admin_count": 2,
            "global_admin_users": [{"id": "admin-1"}, {"id": "admin-2"}],
        },
        "entra003": {
            "authorization_policy": {
                "allowInvitesFrom": "adminsAndGuestInviters",
                "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
                "defaultUserRolePermissions": {
                    "allowedToCreateApps": False,
                    "allowedToCreateTenants": False,
                    "allowedToCreateSecurityGroups": False,
                    "allowedToReadBitlockerKeysForOwnedDevice": False,
                    "permissionGrantPoliciesAssigned": [],
                },
            },
            "m365_group_creation": {"enabled": False},
        },
        "entra004": {
            "join_scope": "selected",
            "local_admin_registration_scope": "none",
            "policy": {
                "userDeviceQuota": 10,
                "azureADJoin": {"localAdmins": {"enableGlobalAdmins": False}},
                "localAdminPassword": {"isEnabled": True},
            },
        },
        "entra005": {
            "admin_consent_request_policy": {"isEnabled": True},
            "default_app_management_policy": {"isEnabled": True},
            "restrictions": {
                "application": {
                    "passwordAddition": deepcopy(password_add),
                    "symmetricKeyAddition": deepcopy(password_add),
                    "passwordLifetime": deepcopy(lifetime),
                    "symmetricKeyLifetime": deepcopy(lifetime),
                    "customPasswordAddition": deepcopy(password_add),
                    "asymmetricKeyLifetime": deepcopy(lifetime),
                },
                "service_principal": {
                    "passwordAddition": deepcopy(password_add),
                    "symmetricKeyAddition": deepcopy(password_add),
                    "passwordLifetime": deepcopy(lifetime),
                    "symmetricKeyLifetime": deepcopy(lifetime),
                    "customPasswordAddition": deepcopy(password_add),
                    "asymmetricKeyLifetime": deepcopy(lifetime),
                },
            },
        },
        "entra006": {
            "member_user_count": 2,
            "mfa_not_capable_member_count": 0,
            "mfa_not_capable_members": [],
        },
        "entra007": {
            "configurations": {
                "sms": {"state": "disabled"},
                "voice": {"state": "disabled"},
                "email": {"state": "disabled"},
                "microsoftAuthenticator": {
                    "state": "enabled",
                    "featureSettings": {
                        "numberMatchingRequiredState": {
                            "state": "enabled",
                            "includeTarget": {"id": "all_users"},
                        }
                    },
                },
            }
        },
    }


FAILURE_MUTATIONS: dict[str, tuple[str, str, object]] = {
    "M365-ENTRA-001": ("entra002", "synced_privileged_user_count", 1),
    "M365-ENTRA-002": ("entra002", "global_admin_count", 5),
    "M365-ENTRA-003": (
        "entra003",
        "authorization_policy.defaultUserRolePermissions.allowedToCreateApps",
        True,
    ),
    "M365-ENTRA-004": (
        "entra003",
        "authorization_policy.defaultUserRolePermissions.allowedToCreateTenants",
        True,
    ),
    "M365-ENTRA-005": (
        "entra003",
        "authorization_policy.defaultUserRolePermissions.allowedToCreateSecurityGroups",
        True,
    ),
    "M365-ENTRA-006": ("entra003", "m365_group_creation.enabled", True),
    "M365-ENTRA-007": ("entra004", "join_scope", "all"),
    "M365-ENTRA-008": ("entra004", "policy.userDeviceQuota", 11),
    "M365-ENTRA-009": (
        "entra004",
        "policy.azureADJoin.localAdmins.enableGlobalAdmins",
        True,
    ),
    "M365-ENTRA-010": ("entra004", "local_admin_registration_scope", "all"),
    "M365-ENTRA-011": ("entra004", "policy.localAdminPassword.isEnabled", False),
    "M365-ENTRA-012": (
        "entra003",
        "authorization_policy.defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice",
        True,
    ),
    "M365-ENTRA-013": (
        "entra003",
        "authorization_policy.defaultUserRolePermissions.permissionGrantPoliciesAssigned",
        ["managePermissionGrantsForSelf.microsoft-user-default-low"],
    ),
    "M365-ENTRA-014": ("entra005", "admin_consent_request_policy.isEnabled", False),
    "M365-ENTRA-015": (
        "entra005",
        "restrictions.application.passwordAddition.state",
        "disabled",
    ),
    "M365-ENTRA-016": (
        "entra005",
        "restrictions.application.passwordLifetime.maxLifetime",
        "P181D",
    ),
    "M365-ENTRA-017": (
        "entra005",
        "restrictions.service_principal.customPasswordAddition.state",
        "disabled",
    ),
    "M365-ENTRA-018": (
        "entra005",
        "restrictions.service_principal.asymmetricKeyLifetime.maxLifetime",
        "P365D",
    ),
    "M365-ENTRA-019": ("entra003", "authorization_policy.guestUserRoleId", "member-role"),
    "M365-ENTRA-020": ("entra003", "authorization_policy.allowInvitesFrom", "everyone"),
    "M365-ENTRA-021": ("entra006", "mfa_not_capable_member_count", 1),
    "M365-ENTRA-022": ("entra007", "configurations.sms.state", "enabled"),
    "M365-ENTRA-023": ("entra007", "configurations.email.state", "enabled"),
    "M365-ENTRA-024": (
        "entra007",
        "configurations.microsoftAuthenticator.featureSettings.numberMatchingRequiredState.includeTarget.id",
        "selected_users",
    ),
}


def _set_path(document: dict[str, Any], path: str, value: object) -> None:
    current: dict[str, Any] = document
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value


def _executions(evidence: dict[str, dict[str, Any]]) -> dict[str, CollectorExecution]:
    return {
        collector_id: CollectorExecution(
            collector_id=collector_id,
            name=collector_id,
            area="entra",
            status=CollectorStatus.SUCCESS,
            data=data,
        )
        for collector_id, data in evidence.items()
    }


@pytest.mark.parametrize("check_id", sorted(FAILURE_MUTATIONS))
def test_each_entra_rule_has_deterministic_pass_and_fail(check_id: str) -> None:
    rule = next(item for item in default_rule_registry().all() if item.check_id == check_id)
    evidence = _passing_evidence()
    permissions = set(rule.required_permissions)

    passed = RuleEngine().evaluate([rule], _executions(evidence), permissions)[0]
    assert passed.status is AssessmentStatus.PASS
    assert passed.remediation
    assert {mapping.framework for mapping in passed.benchmark} == {"CIS", "NIST"}

    collector_id, path, bad_value = FAILURE_MUTATIONS[check_id]
    _set_path(evidence[collector_id], path, bad_value)
    failed = RuleEngine().evaluate([rule], _executions(evidence), permissions)[0]
    assert failed.status is AssessmentStatus.FAIL


def test_phase_two_defines_exactly_twenty_four_entra_rules() -> None:
    rules = [
        rule for rule in default_rule_registry().all() if rule.check_id.startswith("M365-ENTRA-")
    ]
    assert len(rules) == 24
    assert set(FAILURE_MUTATIONS) == {rule.check_id for rule in rules}


def test_permission_gap_is_not_reported_as_failure() -> None:
    rule = next(item for item in default_rule_registry().all() if item.check_id == "M365-ENTRA-021")
    result = RuleEngine().evaluate([rule], _executions(_passing_evidence()), set())[0]
    assert result.status is AssessmentStatus.NOT_ASSESSED
    assert "AuditLog.Read.All" in result.observation
