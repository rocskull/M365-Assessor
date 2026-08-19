from __future__ import annotations

import asyncio
from typing import Any

from m365_assessor.collectors.base import (
    CollectionContext,
    Collector,
    CollectorMetadata,
    NormalizedCollection,
)
from m365_assessor.core.graph import GraphApiError, GraphCollection
from m365_assessor.models.enums import CollectorStatus

GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
GROUP_UNIFIED_TEMPLATE_ID = "62375ab9-6b52-47ed-826b-58e47e0e304b"


def _totals(collections: list[GraphCollection]) -> tuple[int, int]:
    return (
        sum(item.objects_collected for item in collections),
        sum(item.pages_collected for item in collections),
    )


def _odata_type(value: object) -> str:
    if not isinstance(value, dict):
        return "unknown"
    raw = value.get("@odata.type")
    return str(raw).rsplit(".", 1)[-1].casefold() if raw else "unknown"


def _membership_scope(value: object, key: str) -> str:
    if not isinstance(value, dict):
        return "unknown"
    membership = value.get(key)
    kind = _odata_type(membership)
    if kind.startswith("all"):
        return "all"
    if kind.startswith("no"):
        return "none"
    if kind.startswith("enumerated"):
        return "selected"
    return "unknown"


class EntraRoleUsersCollector(Collector):
    metadata = CollectorMetadata(
        id="entra002",
        name="Entra privileged users and roles",
        description="Collects users, active directory role definitions, and active assignments.",
        area="entra",
        required_permissions={
            "User.Read.All",
            "RoleManagement.Read.Directory",
            "GroupMember.Read.All",
        },
        expected_api_calls=[
            "GET /users (paged)",
            "GET /roleManagement/directory/roleDefinitions (paged)",
            "GET /roleManagement/directory/roleAssignments?$expand=principal (paged)",
            "GET /groups/{id}/transitiveMembers/microsoft.graph.user (role groups only)",
        ],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        users, definitions, assignments = await asyncio.gather(
            context.graph.paginate(
                "/users",
                params={
                    "$select": (
                        "id,displayName,userPrincipalName,userType,accountEnabled,"
                        "onPremisesSyncEnabled"
                    )
                },
            ),
            context.graph.paginate(
                "/roleManagement/directory/roleDefinitions",
                params={"$select": "id,displayName,templateId,isBuiltIn"},
            ),
            context.graph.paginate(
                "/roleManagement/directory/roleAssignments",
                params={"$expand": "principal"},
            ),
        )
        collections = [users, definitions, assignments]
        users_by_id = {str(item.get("id")): item for item in users.items if item.get("id")}
        definitions_by_id = {
            str(item.get("id")): item for item in definitions.items if item.get("id")
        }
        normalized_assignments: list[dict[str, Any]] = []
        privileged_users: dict[str, dict[str, Any]] = {}
        api_errors: list[str] = []

        for assignment in assignments.items:
            role = definitions_by_id.get(str(assignment.get("roleDefinitionId")), {})
            principal = assignment.get("principal")
            principal_type = _odata_type(principal)
            principal_id = str(assignment.get("principalId", ""))
            assigned_users: list[dict[str, Any]] = []
            if principal_type == "user":
                user = users_by_id.get(principal_id)
                if user:
                    assigned_users = [user]
            elif principal_type == "group" and principal_id:
                try:
                    members = await context.graph.paginate(
                        f"/groups/{principal_id}/transitiveMembers/microsoft.graph.user",
                        params={
                            "$select": (
                                "id,displayName,userPrincipalName,userType,accountEnabled,"
                                "onPremisesSyncEnabled"
                            )
                        },
                    )
                    collections.append(members)
                    assigned_users = members.items
                    for user in members.items:
                        if user.get("id"):
                            users_by_id[str(user["id"])] = user
                except GraphApiError as exc:
                    api_errors.append(
                        f"Unable to expand role-assignable group {principal_id}: HTTP "
                        f"{exc.status_code or 'unknown'}"
                    )
            user_ids = sorted({str(user.get("id")) for user in assigned_users if user.get("id")})
            for user_id in user_ids:
                privileged_users[user_id] = users_by_id[user_id]
            normalized_assignments.append(
                {
                    "id": assignment.get("id"),
                    "roleDefinitionId": assignment.get("roleDefinitionId"),
                    "roleTemplateId": role.get("templateId"),
                    "roleDisplayName": role.get("displayName"),
                    "principalId": principal_id,
                    "principalType": principal_type,
                    "resolvedUserIds": user_ids,
                    "directoryScopeId": assignment.get("directoryScopeId"),
                }
            )

        global_admin_ids = sorted(
            {
                user_id
                for item in normalized_assignments
                if item["roleTemplateId"] == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
                for user_id in item["resolvedUserIds"]
            }
        )
        privileged = list(privileged_users.values())
        synced_privileged = [
            user
            for user in privileged
            if user.get("onPremisesSyncEnabled") is True and user.get("accountEnabled") is not False
        ]
        total_objects, total_pages = _totals(collections)
        return NormalizedCollection(
            status=CollectorStatus.PARTIAL if api_errors else CollectorStatus.SUCCESS,
            data={
                "users": list(users_by_id.values()),
                "role_definitions": definitions.items,
                "role_assignments": normalized_assignments,
                "privileged_users": privileged,
                "synced_privileged_users": synced_privileged,
                "synced_privileged_user_count": len(synced_privileged),
                "global_admin_users": [
                    users_by_id[user_id] for user_id in global_admin_ids if user_id in users_by_id
                ],
                "global_admin_count": len(global_admin_ids),
            },
            objects_collected=total_objects,
            pages_collected=total_pages,
            api_errors=api_errors,
            limitation_reason=(
                "One or more role-assignable groups could not be expanded." if api_errors else None
            ),
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        required = {"users", "role_definitions", "role_assignments"}
        return (
            ["Role collection is missing normalized data."]
            if not required <= collection.data.keys()
            else []
        )

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get(
                "/roleManagement/directory/roleDefinitions", params={"$top": "1"}
            )
            return True
        except GraphApiError:
            return False


class EntraAuthorizationCollector(Collector):
    metadata = CollectorMetadata(
        id="entra003",
        name="Entra authorization and group settings",
        description="Collects tenant authorization policy and Microsoft 365 group settings.",
        area="entra",
        required_permissions={"Policy.Read.All", "GroupSettings.Read.All"},
        expected_api_calls=[
            "GET /policies/authorizationPolicy",
            "GET /groupSettings (paged)",
        ],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        authorization, settings = await asyncio.gather(
            context.graph.get("/policies/authorizationPolicy"),
            context.graph.paginate("/groupSettings"),
        )
        normalized_settings: dict[str, dict[str, str]] = {}
        for setting in settings.items:
            name = str(setting.get("displayName", setting.get("templateId", "unknown")))
            values = setting.get("values", [])
            normalized_settings[name] = {
                str(item.get("name")): str(item.get("value"))
                for item in values
                if isinstance(item, dict) and item.get("name")
            }
        unified = normalized_settings.get("Group.Unified")
        group_creation_source = "configured" if unified is not None else "service_default"
        group_creation_value = (unified or {}).get("EnableGroupCreation", "true").casefold()
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={
                "authorization_policy": authorization,
                "group_settings": normalized_settings,
                "m365_group_creation": {
                    "enabled": group_creation_value == "true",
                    "source": group_creation_source,
                    "allowed_group_id": (unified or {}).get("GroupCreationAllowedGroupId", ""),
                },
            },
            objects_collected=1 + settings.objects_collected,
            pages_collected=1 + settings.pages_collected,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        return (
            [] if "authorization_policy" in collection.data else ["Authorization policy missing."]
        )

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/policies/authorizationPolicy")
            return True
        except GraphApiError:
            return False


class EntraDevicePolicyCollector(Collector):
    metadata = CollectorMetadata(
        id="entra004",
        name="Entra device registration policy",
        description=(
            "Collects tenant-wide join, registration, quota, local admin, and LAPS settings."
        ),
        area="entra",
        required_permissions={"Policy.Read.DeviceConfiguration"},
        expected_api_calls=["GET /policies/deviceRegistrationPolicy"],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        policy = await context.graph.get("/policies/deviceRegistrationPolicy")
        join = policy.get("azureADJoin", {})
        local_admins = join.get("localAdmins", {}) if isinstance(join, dict) else {}
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={
                "policy": policy,
                "join_scope": _membership_scope(join, "allowedToJoin"),
                "registration_scope": _membership_scope(
                    policy.get("azureADRegistration", {}), "allowedToRegister"
                ),
                "local_admin_registration_scope": _membership_scope(
                    local_admins, "registeringUsers"
                ),
            },
            objects_collected=1,
            pages_collected=1,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        return [] if "policy" in collection.data else ["Device registration policy missing."]

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/policies/deviceRegistrationPolicy")
            return True
        except GraphApiError:
            return False


def _index_restrictions(policy: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    output: dict[str, dict[str, dict[str, Any]]] = {}
    for normalized_name, source_name in (
        ("application", "applicationRestrictions"),
        ("service_principal", "servicePrincipalRestrictions"),
    ):
        source = policy.get(source_name, {})
        source = source if isinstance(source, dict) else {}
        indexed: dict[str, dict[str, Any]] = {}
        for credential_kind in ("passwordCredentials", "keyCredentials"):
            restrictions = source.get(credential_kind, [])
            if not isinstance(restrictions, list):
                continue
            for restriction in restrictions:
                if isinstance(restriction, dict) and restriction.get("restrictionType"):
                    indexed[str(restriction["restrictionType"])] = restriction
        output[normalized_name] = indexed
    return output


class EntraApplicationPolicyCollector(Collector):
    metadata = CollectorMetadata(
        id="entra005",
        name="Entra application and consent policy",
        description=(
            "Collects admin consent workflow and tenant application credential restrictions."
        ),
        area="entra",
        required_permissions={"Policy.Read.All"},
        expected_api_calls=[
            "GET /policies/adminConsentRequestPolicy",
            "GET /policies/defaultAppManagementPolicy",
        ],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        admin_consent, app_policy = await asyncio.gather(
            context.graph.get("/policies/adminConsentRequestPolicy"),
            context.graph.get("/policies/defaultAppManagementPolicy"),
        )
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={
                "admin_consent_request_policy": admin_consent,
                "default_app_management_policy": app_policy,
                "restrictions": _index_restrictions(app_policy),
            },
            objects_collected=2,
            pages_collected=2,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        required = {"admin_consent_request_policy", "default_app_management_policy"}
        return (
            ["Application policy evidence missing."]
            if not required <= collection.data.keys()
            else []
        )

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/policies/adminConsentRequestPolicy")
            return True
        except GraphApiError:
            return False


class EntraMfaRegistrationCollector(Collector):
    metadata = CollectorMetadata(
        id="entra006",
        name="Entra MFA registration",
        description="Collects the paged authentication-method registration report.",
        area="entra",
        required_permissions={"AuditLog.Read.All"},
        expected_api_calls=["GET /reports/authenticationMethods/userRegistrationDetails (paged)"],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        registrations = await context.graph.paginate(
            "/reports/authenticationMethods/userRegistrationDetails"
        )
        members = [item for item in registrations.items if item.get("userType") == "member"]
        not_capable = [item for item in members if item.get("isMfaCapable") is not True]
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={
                "registrations": registrations.items,
                "member_user_count": len(members),
                "mfa_not_capable_member_count": len(not_capable),
                "mfa_not_capable_members": not_capable,
            },
            objects_collected=registrations.objects_collected,
            pages_collected=registrations.pages_collected,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        return [] if "registrations" in collection.data else ["MFA registration report missing."]

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get(
                "/reports/authenticationMethods/userRegistrationDetails", params={"$top": "1"}
            )
            return True
        except GraphApiError:
            return False


class EntraAuthenticationMethodsCollector(Collector):
    metadata = CollectorMetadata(
        id="entra007",
        name="Entra authentication methods policy",
        description="Collects tenant authentication method and Microsoft Authenticator settings.",
        area="entra",
        required_permissions={"Policy.Read.AuthenticationMethod"},
        expected_api_calls=[
            "GET /policies/authenticationMethodsPolicy",
            "GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{method}",
        ],
    )
    _METHODS = ("microsoftAuthenticator", "sms", "voice", "email")

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        policy, *configurations = await asyncio.gather(
            context.graph.get("/policies/authenticationMethodsPolicy"),
            *(
                context.graph.get(
                    "/policies/authenticationMethodsPolicy/"
                    f"authenticationMethodConfigurations/{method}"
                )
                for method in self._METHODS
            ),
        )
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={
                "policy": policy,
                "configurations": dict(zip(self._METHODS, configurations, strict=True)),
            },
            objects_collected=1 + len(configurations),
            pages_collected=1 + len(configurations),
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        configurations = collection.data.get("configurations")
        if not isinstance(configurations, dict) or set(self._METHODS) - configurations.keys():
            return ["One or more authentication method configurations are missing."]
        return []

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/policies/authenticationMethodsPolicy")
            return True
        except GraphApiError:
            return False


class EntraDirectoryInventoryCollector(Collector):
    metadata = CollectorMetadata(
        id="entra008",
        name="Entra directory inventory",
        description="Collects groups, devices, applications, service principals, and OAuth grants.",
        area="entra",
        required_permissions={
            "Group.Read.All",
            "Device.Read.All",
            "Application.Read.All",
            "DelegatedPermissionGrant.Read.All",
        },
        expected_api_calls=[
            "GET /groups (paged)",
            "GET /devices (paged)",
            "GET /applications (paged)",
            "GET /servicePrincipals (paged)",
            "GET /oauth2PermissionGrants (paged)",
        ],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        names_and_paths = {
            "groups": "/groups",
            "devices": "/devices",
            "applications": "/applications",
            "service_principals": "/servicePrincipals",
            "oauth_permission_grants": "/oauth2PermissionGrants",
        }
        collections = await asyncio.gather(
            *(context.graph.paginate(path) for path in names_and_paths.values())
        )
        objects, pages = _totals(list(collections))
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={
                name: collection.items
                for name, collection in zip(names_and_paths, collections, strict=True)
            },
            objects_collected=objects,
            pages_collected=pages,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        return [] if "applications" in collection.data else ["Directory inventory missing."]

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/applications", params={"$top": "1"})
            return True
        except GraphApiError:
            return False


class EntraConditionalAccessCollector(Collector):
    metadata = CollectorMetadata(
        id="entra009",
        name="Entra Conditional Access",
        description="Collects Conditional Access policies and named locations.",
        area="entra",
        required_permissions={"Policy.Read.All"},
        expected_api_calls=[
            "GET /identity/conditionalAccess/policies (paged)",
            "GET /identity/conditionalAccess/namedLocations (paged)",
        ],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        policies, locations = await asyncio.gather(
            context.graph.paginate("/identity/conditionalAccess/policies"),
            context.graph.paginate("/identity/conditionalAccess/namedLocations"),
        )
        objects, pages = _totals([policies, locations])
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={"policies": policies.items, "named_locations": locations.items},
            objects_collected=objects,
            pages_collected=pages,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        return [] if "policies" in collection.data else ["Conditional Access policies missing."]

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/identity/conditionalAccess/policies", params={"$top": "1"})
            return True
        except GraphApiError:
            return False


class EntraExternalCollaborationCollector(Collector):
    metadata = CollectorMetadata(
        id="entra010",
        name="Entra cross-tenant access",
        description="Collects cross-tenant default and partner-specific access settings.",
        area="entra",
        required_permissions={"Policy.Read.All"},
        expected_api_calls=[
            "GET /policies/crossTenantAccessPolicy/default",
            "GET /policies/crossTenantAccessPolicy/partners (paged)",
        ],
    )

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        default, partners = await asyncio.gather(
            context.graph.get("/policies/crossTenantAccessPolicy/default"),
            context.graph.paginate("/policies/crossTenantAccessPolicy/partners"),
        )
        return NormalizedCollection(
            status=CollectorStatus.SUCCESS,
            data={"default": default, "partners": partners.items},
            objects_collected=1 + partners.objects_collected,
            pages_collected=1 + partners.pages_collected,
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        return [] if "default" in collection.data else ["Cross-tenant default policy missing."]

    async def health_check(self, context: CollectionContext) -> bool:
        try:
            await context.graph.get("/policies/crossTenantAccessPolicy/default")
            return True
        except GraphApiError:
            return False


def entra_collectors() -> list[Collector]:
    return [
        EntraRoleUsersCollector(),
        EntraAuthorizationCollector(),
        EntraDevicePolicyCollector(),
        EntraApplicationPolicyCollector(),
        EntraMfaRegistrationCollector(),
        EntraAuthenticationMethodsCollector(),
        EntraDirectoryInventoryCollector(),
        EntraConditionalAccessCollector(),
        EntraExternalCollaborationCollector(),
    ]
