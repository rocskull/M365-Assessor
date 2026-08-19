# Organization-owned Microsoft Entra app registration

This guide configures `m365-assessor` for an internal Microsoft 365 assessment using an application
registration owned by the organization being assessed. The Python application remains on the
assessor's workstation. The Entra app registration supplies its OAuth identity, permission request,
and consent boundary; no source code is uploaded to Microsoft 365.

Use this model when each organization should independently own, approve, audit, and revoke the
assessment application's access. Repeat the procedure in every client tenant. Each registration gets
a different Application (client) ID.

## Result

The completed configuration has this relationship:

```text
Assessor workstation
  └─ m365-assessor
       └─ Application (client) ID
            └─ Client-owned Entra app registration
                 └─ Delegated read permissions and admin consent
                      └─ Client Microsoft 365 tenant
```

The client ID and tenant ID are identifiers, not secrets. Interactive authentication does not require
a client secret. Never place a password, access token, refresh token, client secret, or private key in
the project configuration.

## Prerequisites

- Permission to create an app registration in the organization's Entra tenant.
- An Entra administrator who can review and grant the required delegated permissions.
- An assessment account permitted to read the selected Microsoft 365 services.
- MFA and a compliant workstation when required by Conditional Access.
- Python 3.12 and `m365-assessor` installed on the assessor workstation.
- The supported Exchange, Teams, SharePoint/PnP, Purview, Fabric, and Az PowerShell modules for the
  service areas being assessed.

Microsoft's application-registration instructions are available at
<https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app>.

## Step 1: create the app registration

1. Sign in to <https://entra.microsoft.com> using an account in the organization being assessed.
2. Confirm the correct directory under **Directories + subscriptions**.
3. Open **Entra ID > App registrations > New registration**.
4. Enter `M365 Security Assessor` as the name.
5. Select **Accounts in this organizational directory only**.
6. Leave the redirect URI empty during initial registration and select **Register**.
7. On **Overview**, record these values:

   - **Application (client) ID**: identifies the assessment application.
   - **Directory (tenant) ID**: identifies the organization being assessed.

Do not use the application Object ID in place of the Application (client) ID.

## Step 2: configure desktop authentication on the same app

Perform this step inside the **M365 Security Assessor** app registration created in Step 1. Do not
create another app registration.

1. In **Entra ID > App registrations**, open **M365 Security Assessor**.
2. Open **Authentication** for this app registration.
3. Select **Add a platform**.
4. Select **Mobile and desktop applications**.
5. Add `http://localhost` as the redirect URI.
6. Under advanced settings, enable **Allow public client flows** so device-code authentication is
   available.
7. Save the configuration.

The localhost redirect is used by MSAL's protected browser-based authorization flow; it is not a
hosted web service. Microsoft documents desktop redirect configuration at
<https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri>.

Do not create a client secret for `--auth interactive` or `--auth device-code`.

## Step 3: add delegated Microsoft Graph permissions to the same app

Remain in—or reopen—the **M365 Security Assessor** app registration created in Step 1. Do not add
these permissions to the assessor's user account or to a different application.

1. Open **API permissions** for **M365 Security Assessor**.
2. Select **Add a permission > Microsoft Graph > Delegated permissions**.
3. Add the permissions needed by the implemented Entra collectors:

| Permission | Purpose in this assessment |
|---|---|
| `User.Read` | Sign-in identity and basic profile |
| `Organization.Read.All` | Tenant organization metadata |
| `User.Read.All` | User and privileged-user evidence |
| `RoleManagement.Read.Directory` | Directory roles and assignments |
| `GroupMember.Read.All` | Role-assignable group membership |
| `Policy.Read.All` | Authorization, consent, Conditional Access, and cross-tenant policies |
| `GroupSettings.Read.All` | Microsoft 365 group settings |
| `Policy.Read.DeviceConfiguration` | Device registration policy |
| `AuditLog.Read.All` | MFA registration reporting evidence |
| `Policy.Read.AuthenticationMethod` | Authentication-method policy |
| `Group.Read.All` | Group inventory |
| `Device.Read.All` | Device inventory |
| `Application.Read.All` | Applications and service principals |
| `DelegatedPermissionGrant.Read.All` | OAuth delegated grants |

The authoritative machine-readable mapping is [`config/permissions.yaml`](../config/permissions.yaml).
Remove permissions for collectors that the organization explicitly excludes from scope. Do not add
write permissions.

These delegated permissions define what the **application is allowed to request while a user is
signed in**. They do not assign Microsoft 365 administrator roles to the application. A role such as
**Global Reader** remains assigned separately to the assessor's user account. During an interactive
scan, access is constrained by both the signed-in user's privileges and the delegated permissions
consented for **M365 Security Assessor**.

## Step 4: review and grant consent

1. Ask an authorized Entra administrator to review every requested permission.
2. In the same **M365 Security Assessor** app registration, open **API permissions** and select
   **Grant admin consent for _organization_**.
3. Confirm the prompt.
4. Verify that the required entries show **Granted for _organization_**.

Admin consent does not grant the signed-in assessor unrestricted administrative access. The user must
still have the directory and service roles required to read the underlying configuration. Microsoft
explains the consent model at
<https://learn.microsoft.com/en-us/entra/identity-platform/application-consent-experience>.

## Step 5: assign service roles and install service modules

### Understand what receives each permission

There are two different permission assignments. They are both required where shown:

1. **Application API permissions** are added to the **M365 Security Assessor** app registration from
   Step 1. They limit which APIs the interactive application can request.
2. **User roles and workload role groups** are assigned to the assessor's user account. They control
   what that signed-in user can read inside Microsoft 365.

Do not assign Teams, SharePoint, Fabric, Exchange, or Purview roles to the app registration for an
interactive assessment. Assign them to the user who selects their account in the Microsoft login
window. The effective permission is the intersection of the application's consent and that user's
roles. Licensing and Conditional Access can restrict access further.

If the assessor already has **Global Reader**, start by testing that account. Do not automatically
add every role below. Global Reader supplies broad read access in several Microsoft 365 services,
including Purview view-only capabilities, but some workload PowerShell and tenant-administration
interfaces enforce an additional service-specific role.

### Recommended role plan

| Service | Preferred assessment role | Where it is assigned | Important limitation |
|---|---|---|---|
| Entra ID | Existing **Global Reader** | Microsoft Entra or Microsoft 365 admin center | The app still needs the delegated Microsoft Graph permissions from Step 3. |
| Exchange Online and Defender for Office 365 | Test **Global Reader** first; if Exchange cmdlets are missing, use the Exchange **View-Only Organization Management** role group | Exchange admin center | A few protection cmdlets can require additional Exchange RBAC in a particular tenant. Add only the missing read role reported by the command test. |
| Microsoft Teams | **Teams Reader** | Microsoft Entra or Microsoft 365 admin center | This is the workload-specific read-only role for the Teams admin center and associated PowerShell controls. Existing Global Reader may already provide the required read access; test before duplicating roles. |
| SharePoint Online and OneDrive | **SharePoint Administrator**, activated only for the assessment window | Microsoft Entra or Microsoft 365 admin center | PnP tenant commands used by this tool require access to the SharePoint tenant administration site. This role can make changes even though `m365-assessor` invokes only fixed `Get-*` commands. Prefer PIM/time-bound assignment and remove or deactivate it after collection. |
| Microsoft Purview | Test **Global Reader** first; otherwise use a custom read-only Purview role group | Microsoft Purview portal | Purview uses its own role groups. Use only the view-only roles listed below; do not add Compliance Administrator merely for convenience. |
| Microsoft Fabric | **Fabric Administrator** | Microsoft Entra or Microsoft 365 admin center | Required only when the optional Fabric collector is in scope. The tenant-settings API also requires `Tenant.Read.All` and an applicable Fabric license. |

The Microsoft role descriptions and current assignment guidance are documented in
[Microsoft 365 admin-role assignment](https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/assign-admin-roles),
[Teams administrator roles](https://learn.microsoft.com/en-us/microsoftteams/using-admin-roles),
[SharePoint Administrator](https://learn.microsoft.com/en-us/sharepoint/sharepoint-admin-role), and
[Fabric tenant-settings API](https://learn.microsoft.com/en-us/rest/api/fabric/admin/tenants/list-tenant-settings).

### Assign a Microsoft Entra or Microsoft 365 service role

Use this procedure for **Teams Reader**, **SharePoint Administrator**, or **Fabric Administrator**:

1. Have an authorized role administrator sign in to <https://admin.microsoft.com>.
2. Open **Users > Active users** and select the assessor's user account.
3. Select **Manage roles**.
4. Select **Show all by category** if the required role is not initially visible.
5. Select only the approved role and then select **Save changes**.
6. Reopen the user and confirm the role is listed.

Alternatively, use <https://entra.microsoft.com> and open **Entra ID > Roles & admins > Roles &
administrators**, select the role, and select **Add assignments**. If the organization uses
Privileged Identity Management (PIM), make the assessor eligible for the role and have them activate
it immediately before collection. A tenant-wide assignment is required for tenant-wide settings;
an administrative-unit-scoped SharePoint or Teams role does not provide access to those services'
admin centers or tenant APIs.

Role changes can take time to propagate. Sign out of old PowerShell sessions and authenticate again
after the assignment or PIM activation.

### Assign the Exchange read-only role group

Use this only when the existing Global Reader session cannot execute one or more of the Exchange
collector commands:

1. Have an Exchange administrator sign in to <https://admin.exchange.microsoft.com>.
2. Open **Roles > Admin roles**.
3. Open **View-Only Organization Management**.
4. Open its **Assigned** or **Members** section and select **Add**.
5. Add the assessor's user account, review the assignment, and save it.
6. After propagation, start a new Exchange Online PowerShell session and validate the fixed command
   set below.

Microsoft describes this role group as able to view the properties of any object in the Exchange
organization. Do not use the write-capable **Organization Management** or **Exchange Administrator**
role unless the client explicitly approves it after a documented read-role gap. See
[Exchange role groups](https://learn.microsoft.com/en-us/exchange/permissions-exo/role-groups).

### Assign a custom read-only Purview role group

Global Reader maps to several Purview view-only roles, so first try the Purview command test below.
If the tenant requires explicit Purview assignment, create a narrowly scoped role group:

1. Have a Purview role administrator sign in to <https://purview.microsoft.com>.
2. Open **Settings > Roles and scopes > Role groups**.
3. Select **Create role group** and name it `M365 Assessor - Purview Read Only`.
4. Add these roles for the evidence currently collected by the tool:

   - **View-Only Audit Logs**
   - **View-Only DLP Compliance Management**
   - **View-Only Retention Management**
   - **Sensitivity Label Reader**

5. Add the assessor's user account as a member.
6. Use organization-wide scope only when the assessment scope is tenant-wide; otherwise use the
   administrative units agreed with the client.
7. Review and save the role group.

Microsoft documents the role-group workflow and the interaction between Global Reader and scoped
Purview roles in [Permissions in Microsoft Purview](https://learn.microsoft.com/en-us/purview/purview-permissions).
Purview role changes can take approximately 30 minutes to apply. If one `Get-*` cmdlet is still
unavailable, record that individual evidence gap instead of adding a broad write-capable role.

### Configure SharePoint PnP authorization

The SharePoint collector uses `Get-PnPTenant`, `Get-PnPTenantSite`, and `Get-PnPExternalUser`. These
commands require access to the SharePoint tenant administration site, and `Get-PnPTenantSite`
specifically requires SharePoint Online administrator access. This is why Global Reader alone should
not be assumed to provide complete SharePoint collection.

The **M365 Security Assessor** app registration must also have the appropriate **SharePoint**
delegated API scope; `Sites.Read.All` under Microsoft Graph is not the same permission. Determine the
minimum permission required by the installed PnP PowerShell version before asking for consent:

```powershell
Import-Module PnP.PowerShell

'Get-PnPTenant', 'Get-PnPTenantSite', 'Get-PnPExternalUser' |
  ForEach-Object { Get-PnPCommandPermission -CommandName $_ } |
  Format-Table CommandName, DelegatedPermissions, MinimumSharePointRole
```

In the Step 1 app registration, open **API permissions > Add a permission > SharePoint > Delegated
permissions**, add the least-privileged common SharePoint scope returned by that check, and have an
administrator grant consent. Some PnP tenant-administration operations can require a scope whose
name appears broader than read-only. If the installed module reports `AllSites.FullControl`, obtain
explicit client approval or exclude the SharePoint collector; do not silently grant it. The tool
still runs only the static read commands listed above. PnP documents this delegated broker model in
[Determining PnP permissions](https://pnp.github.io/powershell/articles/determinepermissions.html).

### Install the required PowerShell modules

Run PowerShell 7 as the assessor account and install the modules for the services in scope:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module MicrosoftTeams -Scope CurrentUser
Install-Module PnP.PowerShell -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser
```

Exchange Online and Purview both use `ExchangeOnlineManagement`. Fabric uses `Az.Accounts`. Verify
the modules are visible to the same `pwsh` executable configured for the tool:

```powershell
Get-Module ExchangeOnlineManagement, MicrosoftTeams, PnP.PowerShell, Az.Accounts `
  -ListAvailable | Select-Object Name, Version, Path
```

### Validate service access before scanning

The following commands are read-only connection and command tests. Run only the blocks for services
that are in scope:

```powershell
# Exchange Online
Connect-ExchangeOnline -Device -ShowBanner:$false
Get-OrganizationConfig | Select-Object AuditDisabled
Get-EXOMailbox -ResultSize 1 | Select-Object DisplayName
Disconnect-ExchangeOnline -Confirm:$false

# Teams
Connect-MicrosoftTeams -TenantId '<directory-tenant-id>'
Get-CsTenantFederationConfiguration | Select-Object AllowedDomains
Get-CsTeamsMeetingPolicy | Select-Object -First 1 -Property Identity
Disconnect-MicrosoftTeams

# SharePoint/PnP
Connect-PnPOnline -Url 'https://tenant-admin.sharepoint.com' `
  -Interactive -ClientId '<application-client-id>'
Get-PnPTenant | Select-Object SharingCapability
Get-PnPTenantSite | Select-Object -First 1 -Property Url
Disconnect-PnPOnline

# Purview
Connect-IPPSSession -Device -ShowBanner:$false
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
Get-DlpCompliancePolicy | Select-Object -First 1 -Property Name
Get-LabelPolicy | Select-Object -First 1 -Property Name
```

For SharePoint, supply the actual tenant administration URL, normally
`https://<tenant>-admin.sharepoint.com`, for both the manual role test and the scan's
`--sharepoint-url` value. Do not use an ordinary site URL for tenant-level collection.

Do not test access with `Set-*`, `New-*`, or `Remove-*` commands. If a test command fails, preserve
the exact cmdlet name and authorization error for the client's administrator. Add only the role or
API permission needed for that command.

Runtime service authorization is reported separately in the Coverage & Permission Report. A service
authorization failure produces `NOT_ASSESSED` or partial coverage rather than a failed security
control. See [Coverage and permissions](permissions.md) for the service matrix.

## Step 6: configure the workstation

For the current PowerShell session:

```powershell
$env:M365_ASSESSOR_CLIENT_ID = "<application-client-id>"
$env:M365_ASSESSOR_TENANT_ID = "<directory-tenant-id>"
```

Alternatively, create `config/config.yaml` from the supplied example:

```yaml
tenant_id: "<directory-tenant-id>"
client_id: "<application-client-id>"
client_name: "Contoso"
auth_method: interactive
output_directory: "D:/M365-Assessments"
frameworks:
  - cis-m365-7.0.0
sharepoint_url: "https://contoso-admin.sharepoint.com"
```

Use either environment variables or a configuration file. When using the file, pass it explicitly to
commands with `--config config/config.yaml`. Command-line options override their corresponding loaded
settings.

## Step 7: validate before collection

Test authentication:

```powershell
m365-assessor auth login `
  --tenant "$env:M365_ASSESSOR_TENANT_ID" `
  --auth interactive
```

Review the permission preflight:

```powershell
m365-assessor permissions `
  --tenant "$env:M365_ASSESSOR_TENANT_ID" `
  --auth interactive
```

Preview scope without collecting tenant data:

```powershell
m365-assessor scan `
  --tenant "$env:M365_ASSESSOR_TENANT_ID" `
  --framework 1 `
  --dry-run
```

Check that the tenant ID, client ID, selected framework, collectors, and required permissions match
the approved assessment plan.

## Step 8: run the assessment

Interactive execution with explicit client ownership:

```powershell
m365-assessor scan `
  --tenant "$env:M365_ASSESSOR_TENANT_ID" `
  --auth interactive `
  --framework 1 `
  --client-name "Contoso" `
  --sharepoint-url "https://contoso-admin.sharepoint.com" `
  -O "D:\M365-Assessments"
```

The output root receives a client-and-timestamp folder such as:

```text
D:\M365-Assessments\Contoso-m365-assessment-20260819-164510\
```

The scan remains read-only. Missing permissions, licenses, modules, or service roles reduce coverage
and are explained in the report; they are not converted into security failures.

## Step 9: verify the audit trail

After authentication and scanning, the organization can review:

- **Entra ID > Enterprise applications > M365 Security Assessor** for the tenant service principal.
- **Sign-in logs** for delegated sign-ins by the assessor.
- **Audit logs** for consent and app-registration changes.
- The generated Permission Coverage sheet for unavailable permissions, collectors, and checks.

The assessment report deliberately excludes credentials and access tokens.

## Step 10: revoke or remove access

When the engagement ends, the organization can choose one of these actions:

- Revoke the app's admin consent if the registration will be retained.
- Disable sign-in for its Enterprise application.
- Delete the Enterprise application and app registration if they were created only for this
  assessment.
- Remove temporary assessor role assignments.
- Remove local environment variables and securely archive or delete assessment evidence according to
  the organization's retention policy.

Deleting an app registration is a tenant configuration change and must be performed by the
organization's administrator, not by `m365-assessor`.

## Repeat for another client

For a separate client-owned assessment, repeat Steps 1 through 10 in that client's tenant. Use that
client's values for both variables:

```powershell
$env:M365_ASSESSOR_CLIENT_ID = "<client-application-client-id>"
$env:M365_ASSESSOR_TENANT_ID = "<client-directory-tenant-id>"
```

Do not reuse one client's single-tenant client ID against another client's tenant.

## Troubleshooting

### `Missing client ID`

The environment variable was not set in the current process and no `client_id` was loaded from
configuration:

```powershell
$env:M365_ASSESSOR_CLIENT_ID = "<application-client-id>"
```

### `AADSTS700016` or application not found

Confirm that the Application (client) ID belongs to the tenant supplied with `--tenant`. Ensure an
Object ID was not copied by mistake.

### Redirect URI error

Confirm the app registration contains a **Mobile and desktop applications** platform with
`http://localhost` registered exactly.

### Consent required

Return to **API permissions** and have an authorized administrator review and grant the required
delegated permissions.

### Conditional Access blocked authentication

Use an approved account and compliant device, or ask the organization's administrator to review the
relevant Conditional Access sign-in event. Do not weaken Conditional Access merely to make the scan
run.

### Graph succeeds but a service collector is unavailable

Graph consent does not guarantee Exchange, Teams, SharePoint, Purview, or Fabric access. Review the
collector's limitation reason, the relevant PowerShell module, service role, license, and explicitly
configured service URL.
