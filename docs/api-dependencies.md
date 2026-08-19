# API and module dependencies

- Microsoft Graph v1.0: organization, users, groups, roles, policies, devices, applications, service
  principals, OAuth grants, Conditional Access, authentication methods, reports, and cross-tenant access
- ExchangeOnlineManagement: Exchange Online and Security & Compliance read cmdlets
- MicrosoftTeams: tenant, federation, file, channel, meeting, messaging, app, and calling policies
- PnP.PowerShell: SharePoint/OneDrive tenant, site, sharing, and external-user evidence
- Microsoft Fabric Admin REST API v1: list tenant settings with continuation support as exposed by the service
- MSAL and Azure Identity: Microsoft identity authentication and managed identity

Microsoft Graph beta endpoints are not used by the built-in collectors. Service interfaces can change;
collector command errors are isolated and reported as coverage limitations rather than false findings.
