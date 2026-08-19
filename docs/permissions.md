# Coverage and permissions

`config/permissions.yaml` maps every permission or runtime service authorization to collectors and
affected checks. Run:

```powershell
m365-assessor permissions --tenant <tenant-id> --auth device-code
```

Graph evidence uses least-privilege read scopes including organization, user, role, group, policy,
device, audit-registration, authentication-method, application, and delegated-grant readers. Exact
scope-to-check relationships are in the matrix rather than hard-coded evaluation functions.

Exchange/Purview, Teams, SharePoint, and Fabric permissions are verified at collection time because
service RBAC is not fully represented by a Microsoft Graph token. Preflight labels these entries
`RUNTIME`, and the final report replaces that uncertainty with collector evidence.

Coverage is calculated from assessed checks when results exist. Partial, unavailable, or failed
collectors reduce the area's state and add explicit reasons. A missing permission or evidence field
produces `NOT_ASSESSED`, never `FAIL`. Forms remains a visible zero-percent limitation because no
supported Forms collector is included.
