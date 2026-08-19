# Authentication

Supported Graph methods are `interactive`, `device-code`, `service-principal`, `certificate`, and
`managed-identity`. Passwords are never accepted or stored.

For client-owned delegated deployments, follow the complete
[organization-owned app-registration guide](organization-owned-app-registration.md).

```powershell
$env:M365_ASSESSOR_CLIENT_ID = "<application-id>"
m365-assessor auth login --tenant <tenant-id> --auth interactive
m365-assessor auth login --tenant <tenant-id> --auth device-code
```

For delegated interactive or device-code authentication, the tenant can be omitted:

```powershell
m365-assessor scan --auth interactive
```

The tool authenticates through the Microsoft `organizations` authority, forces account selection,
discovers the tenant ID from the returned token, displays the tenant and signed-in identity, and asks
for confirmation before any collectors run. Use `--yes` to acknowledge the discovered tenant in a
non-interactive invocation. Tenant discovery requires an application registration that supports
accounts in multiple organizational directories. Service-principal and certificate authentication
continue to require an explicit tenant ID.

Client secrets are read only from the environment variable named by `client_secret_env`. Certificate
private-key passwords are read only from `certificate_password_env`. MSAL serialized tokens are stored
through the OS keyring; if no secure backend exists, the cache is memory-only.

Exchange/Purview, Teams, SharePoint, and Fabric use their Microsoft-supported service interfaces and
independently enforce service RBAC. Device flow is used for interactive service collection. Unattended
Exchange/Purview and Teams collection uses application/certificate authentication. PnP SharePoint
certificate collection expects the PFX file configured by `service_certificate_path`; Graph MSAL
certificate authentication continues to use the PEM `certificate_path`. Fabric uses Az.Accounts to request a token for
`https://api.fabric.microsoft.com` and needs `Tenant.Read.All` plus Fabric administrator authorization.

Set `exchange_organization` to the tenant's initial `*.onmicrosoft.com` domain for unattended Exchange
and Purview collection. Set `sharepoint_url` to the tenant administration URL when discovery is not
available.

Authentication failures distinguish invalid tenant/client, consent, expired credentials, Conditional
Access, missing modules, and service RBAC. Access and refresh tokens, secrets, and private keys are
never included in logs, caches, databases, or reports.
