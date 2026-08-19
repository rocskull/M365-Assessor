from __future__ import annotations

import httpx
import pytest

from m365_assessor.collectors.base import CollectionContext
from m365_assessor.collectors.registry import default_registry
from m365_assessor.config import Settings
from m365_assessor.models.enums import CollectorStatus


def _response_for(path: str) -> dict[str, object]:
    if path == "/v1.0/users":
        return {
            "value": [
                {
                    "id": "user-1",
                    "displayName": "Cloud Admin",
                    "userPrincipalName": "admin@example.invalid",
                    "userType": "Member",
                    "accountEnabled": True,
                    "onPremisesSyncEnabled": False,
                }
            ]
        }
    if path == "/v1.0/roleManagement/directory/roleDefinitions":
        return {
            "value": [
                {
                    "id": "role-1",
                    "displayName": "Global Administrator",
                    "templateId": "62e90394-69f5-4237-9190-012177145e10",
                }
            ]
        }
    if path == "/v1.0/roleManagement/directory/roleAssignments":
        return {
            "value": [
                {
                    "id": "assignment-1",
                    "roleDefinitionId": "role-1",
                    "principalId": "user-1",
                    "principal": {"@odata.type": "#microsoft.graph.user", "id": "user-1"},
                }
            ]
        }
    if path == "/v1.0/policies/authorizationPolicy":
        return {
            "id": "authorizationPolicy",
            "allowInvitesFrom": "adminsAndGuestInviters",
            "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
            "defaultUserRolePermissions": {
                "allowedToCreateApps": False,
                "allowedToCreateTenants": False,
                "allowedToCreateSecurityGroups": False,
                "allowedToReadBitlockerKeysForOwnedDevice": False,
                "permissionGrantPoliciesAssigned": [],
            },
        }
    if path == "/v1.0/groupSettings":
        return {
            "value": [
                {
                    "displayName": "Group.Unified",
                    "values": [
                        {"name": "EnableGroupCreation", "value": "false"},
                        {"name": "GroupCreationAllowedGroupId", "value": "group-1"},
                    ],
                }
            ]
        }
    if path == "/v1.0/policies/deviceRegistrationPolicy":
        return {
            "userDeviceQuota": 10,
            "azureADRegistration": {
                "allowedToRegister": {
                    "@odata.type": "#microsoft.graph.enumeratedDeviceRegistrationMembership"
                }
            },
            "azureADJoin": {
                "allowedToJoin": {
                    "@odata.type": "#microsoft.graph.enumeratedDeviceRegistrationMembership"
                },
                "localAdmins": {
                    "enableGlobalAdmins": False,
                    "registeringUsers": {
                        "@odata.type": "#microsoft.graph.noDeviceRegistrationMembership"
                    },
                },
            },
            "localAdminPassword": {"isEnabled": True},
        }
    if path == "/v1.0/policies/adminConsentRequestPolicy":
        return {"isEnabled": True, "reviewers": [{"query": "/users/reviewer"}]}
    if path == "/v1.0/policies/defaultAppManagementPolicy":
        password_types = [
            "passwordAddition",
            "symmetricKeyAddition",
            "passwordLifetime",
            "symmetricKeyLifetime",
            "customPasswordAddition",
        ]
        password_credentials = [
            {
                "restrictionType": item,
                "state": "enabled",
                "maxLifetime": "P180D" if "Lifetime" in item else None,
                "restrictForAppsCreatedAfterDateTime": "0001-01-01T00:00:00Z",
            }
            for item in password_types
        ]
        keys = [
            {
                "restrictionType": "asymmetricKeyLifetime",
                "state": "enabled",
                "maxLifetime": "P180D",
            }
        ]
        return {
            "isEnabled": True,
            "applicationRestrictions": {
                "passwordCredentials": password_credentials,
                "keyCredentials": keys,
            },
            "servicePrincipalRestrictions": {
                "passwordCredentials": password_credentials,
                "keyCredentials": keys,
            },
        }
    if path == "/v1.0/reports/authenticationMethods/userRegistrationDetails":
        return {
            "value": [
                {
                    "id": "user-1",
                    "userType": "member",
                    "isMfaCapable": True,
                    "methodsRegistered": ["microsoftAuthenticatorPush"],
                }
            ]
        }
    if path == "/v1.0/policies/authenticationMethodsPolicy":
        return {"id": "authenticationMethodsPolicy", "policyVersion": "1.5"}
    if "/authenticationMethodConfigurations/" in path:
        method = path.rsplit("/", 1)[-1]
        if method == "microsoftAuthenticator":
            return {
                "id": method,
                "state": "enabled",
                "featureSettings": {
                    "numberMatchingRequiredState": {
                        "state": "enabled",
                        "includeTarget": {"id": "all_users"},
                    }
                },
            }
        return {"id": method, "state": "disabled"}
    if path in {
        "/v1.0/groups",
        "/v1.0/devices",
        "/v1.0/applications",
        "/v1.0/servicePrincipals",
        "/v1.0/oauth2PermissionGrants",
        "/v1.0/identity/conditionalAccess/policies",
        "/v1.0/identity/conditionalAccess/namedLocations",
        "/v1.0/policies/crossTenantAccessPolicy/partners",
    }:
        return {"value": [{"id": path.rsplit("/", 1)[-1] + "-1"}]}
    if path == "/v1.0/policies/crossTenantAccessPolicy/default":
        return {"id": "default", "isServiceDefault": False}
    raise AssertionError(f"Unexpected Graph path: {path}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("collector_id", "expected_key"),
    [
        ("entra002", "global_admin_count"),
        ("entra003", "authorization_policy"),
        ("entra004", "join_scope"),
        ("entra005", "restrictions"),
        ("entra006", "mfa_not_capable_member_count"),
        ("entra007", "configurations"),
        ("entra008", "applications"),
        ("entra009", "policies"),
        ("entra010", "partners"),
    ],
)
async def test_each_entra_collector_normalizes_mock_graph(
    graph_factory, collector_id: str, expected_key: str
) -> None:
    graph = graph_factory(
        httpx.MockTransport(
            lambda request: httpx.Response(200, json=_response_for(request.url.path))
        )
    )
    collector = default_registry().get(collector_id)
    context = CollectionContext(
        graph=graph,
        settings=Settings(),
        granted_permissions=collector.metadata.required_permissions,
    )
    result = await collector.collect(context)
    assert result.status is CollectorStatus.SUCCESS
    assert expected_key in result.data
    assert collector.validate(result) == []


@pytest.mark.asyncio
async def test_role_collector_marks_group_expansion_gap_partial(graph_factory) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/transitiveMembers/" in request.url.path:
            return httpx.Response(403, json={"error": {"code": "Forbidden"}})
        payload = _response_for(request.url.path)
        if request.url.path.endswith("/roleAssignments"):
            payload = {
                "value": [
                    {
                        "id": "assignment-1",
                        "roleDefinitionId": "role-1",
                        "principalId": "group-1",
                        "principal": {"@odata.type": "#microsoft.graph.group", "id": "group-1"},
                    }
                ]
            }
        return httpx.Response(200, json=payload)

    graph = graph_factory(httpx.MockTransport(handler))
    collector = default_registry().get("entra002")
    result = await collector.collect(
        CollectionContext(
            graph=graph,
            settings=Settings(),
            granted_permissions=collector.metadata.required_permissions,
        )
    )
    assert result.status is CollectorStatus.PARTIAL
    assert result.api_errors
