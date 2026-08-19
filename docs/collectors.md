# Collectors

Collectors are independent plugins with metadata, required permissions, expected calls, `collect()`,
`validate()`, and `health_check()`. Collection and evaluation are intentionally separate.

| IDs | Service | Evidence domains |
|---|---|---|
| `entra001`-`entra010` | Entra ID | tenant, users, roles, authorization, devices, apps, MFA, methods, Conditional Access, cross-tenant access |
| `exo001`-`exo003` | Exchange Online / Defender | organization, mail flow, mailbox audit, protection and domain policies |
| `teams001`-`teams003` | Microsoft Teams | federation, files/channels, meeting, messaging, apps and calling policies |
| `sps001`-`sps002` | SharePoint / OneDrive | tenant policy, sites, external users and sharing defaults |
| `purview001`-`purview002` | Microsoft Purview | unified audit, DLP, labels and retention |
| `fabric001` | Microsoft Fabric | tenant settings through the supported administration API |

Graph collectors paginate every collection and record pages, objects, and API errors. Non-Graph
collectors use static read-only commands through Microsoft-supported PowerShell modules. A failed
command is retained as a partial collector result when other evidence is usable. A failed collector
never terminates other areas.

For deterministic offline replay, set `evidence_input` to a JSON object keyed by service name. This
is also the service mock format used by tests. Third-party packages may register collectors through
the `m365_assessor.collectors` entry-point group.
