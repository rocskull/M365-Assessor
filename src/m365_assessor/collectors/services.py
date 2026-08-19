from __future__ import annotations

import re
from typing import Any

from m365_assessor.collectors.base import (
    CollectionContext,
    Collector,
    CollectorMetadata,
    NormalizedCollection,
)
from m365_assessor.core.service import ServiceCollectionError
from m365_assessor.models.enums import CollectorStatus


def _snake(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.replace("-", "_").replace(" ", "_").casefold()


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {_snake(str(key)): _normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


class PowerShellCommandCollector(Collector):
    service: str
    commands: dict[str, str]
    singleton_keys: set[str] = set()

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        clients = context.service_clients or {}
        client = clients.get(self.service)
        if client is None:
            return NormalizedCollection(
                status=CollectorStatus.NOT_ASSESSED,
                limitation_reason=(
                    f"No {self.service} service client is configured. Enable service collection "
                    "or provide cached evidence."
                ),
            )
        try:
            payload = await client.collect(self.commands)
        except ServiceCollectionError as exc:
            return NormalizedCollection(
                status=CollectorStatus.NOT_ASSESSED,
                limitation_reason=str(exc),
            )
        normalized = _normalize(payload.data)
        for key in self.singleton_keys:
            value = normalized.get(key)
            if isinstance(value, list) and len(value) == 1:
                normalized[key] = value[0]
        object_count = sum(
            len(item) if isinstance(item, list) else int(item is not None)
            for item in normalized.values()
        )
        return NormalizedCollection(
            status=CollectorStatus.PARTIAL if payload.errors else CollectorStatus.SUCCESS,
            data=normalized,
            objects_collected=object_count,
            pages_collected=1,
            api_errors=payload.errors,
            limitation_reason=(
                "One or more supported service commands were unavailable; available evidence "
                "was retained."
                if payload.errors
                else None
            ),
        )

    def validate(self, collection: NormalizedCollection) -> list[str]:
        if collection.status in {CollectorStatus.NOT_ASSESSED, CollectorStatus.ERROR}:
            return []
        return [] if collection.data else ["Service returned no usable evidence."]

    async def health_check(self, context: CollectionContext) -> bool:
        client = (context.service_clients or {}).get(self.service)
        return bool(client and await client.health_check())


class ExchangeOrganizationCollector(PowerShellCommandCollector):
    service = "exchange"
    singleton_keys = {"organization_config", "transport_config", "external_sender"}
    metadata = CollectorMetadata(
        id="exo001",
        name="Exchange organization configuration",
        description="Collects organization, transport, OWA, remote-domain, and sender settings.",
        area="exchange",
        expected_api_calls=["Exchange Online PowerShell read cmdlets"],
    )
    commands = {
        "organization_config": (
            "Get-OrganizationConfig | Select-Object AuditDisabled,OAuth2ClientProfileEnabled,"
            "MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled,"
            "MailTipsGroupMetricsEnabled,MailTipsLargeAudienceThreshold,RejectDirectSend"
        ),
        "transport_config": (
            "Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled,"
            "ExternalPostmasterAddress"
        ),
        "external_sender": "Get-ExternalInOutlook | Select-Object Enabled",
        "owa_policies": (
            "Get-OwaMailboxPolicy | Select-Object Identity,AdditionalStorageProvidersAvailable,"
            "PersonalAccountsEnabled"
        ),
        "remote_domains": "Get-RemoteDomain | Select-Object Identity,AutoForwardEnabled",
    }


class ExchangeProtectionCollector(PowerShellCommandCollector):
    service = "exchange"
    singleton_keys = {"atp_policy"}
    metadata = CollectorMetadata(
        id="exo002",
        name="Exchange threat protection",
        description="Collects supported Defender for Office 365 and anti-spam policy evidence.",
        area="exchange",
        expected_api_calls=["Exchange Online PowerShell protection-policy read cmdlets"],
    )
    commands = {
        "safe_links": (
            "Get-SafeLinksPolicy | Select-Object Identity,IsEnabled,EnableSafeLinksForEmail,"
            "EnableSafeLinksForTeams,EnableSafeLinksForOffice"
        ),
        "malware_filter": (
            "Get-MalwareFilterPolicy | Select-Object Identity,EnableFileFilter,"
            "EnableInternalSenderAdminNotifications"
        ),
        "safe_attachments": (
            "Get-SafeAttachmentPolicy | Select-Object Identity,Enable,Action,Redirect,QuarantineTag"
        ),
        "atp_policy": (
            "Get-AtpPolicyForO365 | Select-Object EnableATPForSPOTeamsODB,"
            "AllowSafeDocsOpen,EnableSafeDocs"
        ),
        "outbound_spam": (
            "Get-HostedOutboundSpamFilterPolicy | Select-Object Identity,"
            "RecipientLimitExternalPerHour,RecipientLimitInternalPerHour,RecipientLimitPerDay,"
            "ActionWhenThresholdReached,NotifyOutboundSpam"
        ),
        "anti_phish": "Get-AntiPhishPolicy | Select-Object Identity,Enabled,PhishThresholdLevel",
        "accepted_domains": "Get-AcceptedDomain | Select-Object DomainName,DomainType",
        "spf_records": (
            "Get-AcceptedDomain | ForEach-Object { $d = $_.DomainName.ToString(); "
            "$txt = @(Resolve-DnsName -Name $d -Type TXT -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Strings -join '' }); [pscustomobject]@{ Domain = $d; "
            "Published = [bool]($txt -match '^v=spf1') } }"
        ),
        "dmarc_records": (
            "Get-AcceptedDomain | ForEach-Object { $d = $_.DomainName.ToString(); "
            "$txt = @(Resolve-DnsName -Name ('_dmarc.' + $d) -Type TXT "
            "-ErrorAction SilentlyContinue | ForEach-Object { $_.Strings -join '' }); "
            "[pscustomobject]@{ Domain = $d; Published = [bool]($txt -match '^v=DMARC1') } }"
        ),
        "dkim": "Get-DkimSigningConfig | Select-Object Domain,Enabled,Status",
        "connection_filter": (
            "Get-HostedConnectionFilterPolicy | Select-Object Identity,IPAllowList,EnableSafeList"
        ),
        "inbound_spam": (
            "Get-HostedContentFilterPolicy | Select-Object Identity,AllowedSenderDomains,"
            "AllowedSenders,EnableEndUserSpamNotifications"
        ),
        "preset_security": (
            "Get-ATPProtectionPolicyRule | Select-Object Identity,State,Priority,"
            "SentTo,ExceptIfSentTo"
        ),
    }


class ExchangeMailflowCollector(PowerShellCommandCollector):
    service = "exchange"
    metadata = CollectorMetadata(
        id="exo003",
        name="Exchange mailbox audit and mail flow",
        description="Collects mailbox auditing, forwarding, bypass, transport rule, and role data.",
        area="exchange",
        expected_api_calls=["Exchange Online PowerShell mailbox and mail-flow read cmdlets"],
    )
    commands = {
        "mailboxes": (
            "Get-EXOMailbox -ResultSize Unlimited -Properties AuditEnabled,AuditAdmin,"
            "AuditDelegate,AuditOwner,ForwardingAddress,ForwardingSmtpAddress,"
            "DeliverToMailboxAndForward | Select-Object ExternalDirectoryObjectId,"
            "PrimarySmtpAddress,RecipientTypeDetails,AuditEnabled,AuditAdmin,AuditDelegate,"
            "AuditOwner,ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward"
        ),
        "audit_bypass": (
            "Get-MailboxAuditBypassAssociation -ResultSize Unlimited | "
            "Select-Object Identity,AuditBypassEnabled"
        ),
        "transport_rules": (
            "Get-TransportRule | Select-Object Identity,State,Mode,RedirectMessageTo,"
            "BlindCopyTo,AddToRecipients,SetSCL,SenderDomainIs,ExceptIfSenderDomainIs"
        ),
        "management_assignments": (
            "Get-ManagementRoleAssignment | Select-Object Name,Role,RoleAssigneeName,Enabled"
        ),
    }


class TeamsTenantCollector(PowerShellCommandCollector):
    service = "teams"
    singleton_keys = {"client_configuration", "federation_configuration"}
    metadata = CollectorMetadata(
        id="teams001",
        name="Teams tenant and federation configuration",
        description="Collects tenant, client, file, channel, and external-access policies.",
        area="teams",
        expected_api_calls=["MicrosoftTeams PowerShell tenant read cmdlets"],
    )
    commands = {
        "client_configuration": "Get-CsTeamsClientConfiguration | Select-Object *",
        "federation_configuration": "Get-CsTenantFederationConfiguration | Select-Object *",
        "federation_policies": "Get-CsExternalAccessPolicy | Select-Object *",
        "files_policies": "Get-CsTeamsFilesPolicy | Select-Object *",
        "channels_policies": "Get-CsTeamsChannelsPolicy | Select-Object *",
    }


class TeamsMeetingCollector(PowerShellCommandCollector):
    service = "teams"
    metadata = CollectorMetadata(
        id="teams002",
        name="Teams meeting policies",
        description="Collects meeting, lobby, anonymous-user, control, chat, and recording policy.",
        area="teams",
        expected_api_calls=["Get-CsTeamsMeetingPolicy"],
    )
    commands = {"meeting_policies": "Get-CsTeamsMeetingPolicy | Select-Object *"}


class TeamsMessagingCollector(PowerShellCommandCollector):
    service = "teams"
    metadata = CollectorMetadata(
        id="teams003",
        name="Teams messaging and application policies",
        description="Collects messaging, app permission, app setup, and calling policies.",
        area="teams",
        expected_api_calls=["MicrosoftTeams PowerShell policy read cmdlets"],
    )
    commands = {
        "messaging_policies": "Get-CsTeamsMessagingPolicy | Select-Object *",
        "app_permission_policies": "Get-CsTeamsAppPermissionPolicy | Select-Object *",
        "app_setup_policies": "Get-CsTeamsAppSetupPolicy | Select-Object *",
        "calling_policies": "Get-CsTeamsCallingPolicy | Select-Object *",
    }


class SharePointTenantCollector(PowerShellCommandCollector):
    service = "sharepoint"
    singleton_keys = {"tenant"}
    metadata = CollectorMetadata(
        id="sps001",
        name="SharePoint and OneDrive tenant policy",
        description="Collects tenant-wide authentication, sharing, guest, link, and sync settings.",
        area="sharepoint",
        expected_api_calls=["PnP PowerShell Get-PnPTenant"],
    )
    commands = {"tenant": "Get-PnPTenant | Select-Object *"}


class SharePointSitesCollector(PowerShellCommandCollector):
    service = "sharepoint"
    metadata = CollectorMetadata(
        id="sps002",
        name="SharePoint and OneDrive sites",
        description="Collects site sharing settings and external-user inventory.",
        area="sharepoint",
        expected_api_calls=["PnP PowerShell site and external-user read cmdlets"],
    )
    commands = {
        "sites": (
            "Get-PnPTenantSite -IncludeOneDriveSites | Select-Object Url,Title,Owner,"
            "SharingCapability,DefaultSharingLinkType,DefaultLinkPermission,"
            "OverrideTenantExternalUserExpirationPolicy,ExternalUserExpirationInDays"
        ),
        "external_users": (
            "Get-PnPExternalUser | Select-Object UniqueId,DisplayName,Email,AcceptedAs"
        ),
    }


class PurviewComplianceCollector(PowerShellCommandCollector):
    service = "purview"
    singleton_keys = {"audit_config"}
    metadata = CollectorMetadata(
        id="purview001",
        name="Purview audit and DLP policies",
        description="Collects unified audit and data loss prevention policy evidence.",
        area="purview",
        expected_api_calls=["Security and Compliance PowerShell read cmdlets"],
    )
    commands = {
        "audit_config": "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled",
        "dlp_policies": "Get-DlpCompliancePolicy | Select-Object Name,Enabled,Mode,Workload",
        "dlp_rules": (
            "Get-DlpComplianceRule | Select-Object Name,Disabled,Policy,"
            "ContentContainsSensitiveInformation"
        ),
    }


class PurviewInformationProtectionCollector(PowerShellCommandCollector):
    service = "purview"
    metadata = CollectorMetadata(
        id="purview002",
        name="Purview information governance",
        description="Collects label publishing, retention, and compliance policy evidence.",
        area="purview",
        expected_api_calls=["Security and Compliance PowerShell governance read cmdlets"],
    )
    commands = {
        "label_policies": (
            "Get-LabelPolicy | Select-Object Name,Enabled,Mode,Labels,ExchangeLocation,"
            "SharePointLocation"
        ),
        "retention_policies": (
            "Get-RetentionCompliancePolicy | Select-Object Name,Enabled,Mode,Workload"
        ),
        "retention_rules": (
            "Get-RetentionComplianceRule | Select-Object Name,Disabled,Policy,RetentionDuration"
        ),
    }


class FabricTenantCollector(PowerShellCommandCollector):
    service = "fabric"
    singleton_keys = {"tenant_settings_json"}
    metadata = CollectorMetadata(
        id="fabric001",
        name="Microsoft Fabric tenant settings",
        description="Collects Fabric/Power BI tenant settings through the supported admin API.",
        area="fabric",
        expected_api_calls=["Power BI admin tenant settings REST API"],
    )
    commands = {
        "tenant_settings_json": (
            "$headers = @{ Authorization = ('Bearer ' + $fabricToken) }; "
            "$uri = 'https://api.fabric.microsoft.com/v1/admin/tenantsettings'; "
            "$items = @(); do { $response = Invoke-M365ReadRest -Uri $uri -Headers $headers; "
            "$items += @($response.value); $uri = $response.continuationUri "
            "} while ($uri); [pscustomobject]@{ value = $items }"
        )
    }

    async def collect(self, context: CollectionContext) -> NormalizedCollection:
        result = await super().collect(context)
        payload = result.data.get("tenant_settings_json")
        if isinstance(payload, dict) and isinstance(payload.get("value"), list):
            payload["tenant_settings"] = payload.pop("value")
            for setting in payload["tenant_settings"]:
                if isinstance(setting, dict):
                    setting["setting_id"] = setting.get("setting_name")
                    setting["setting_name"] = setting.get("title") or setting.get("setting_name")
        return result


def service_collectors() -> list[Collector]:
    return [
        ExchangeOrganizationCollector(),
        ExchangeProtectionCollector(),
        ExchangeMailflowCollector(),
        TeamsTenantCollector(),
        TeamsMeetingCollector(),
        TeamsMessagingCollector(),
        SharePointTenantCollector(),
        SharePointSitesCollector(),
        PurviewComplianceCollector(),
        PurviewInformationProtectionCollector(),
        FabricTenantCollector(),
    ]
