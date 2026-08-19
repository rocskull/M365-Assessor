# Troubleshooting

- **Consent required:** grant only the permission identified in the coverage report and repeat login.
- **Conditional Access:** use an approved assessor identity, device, and location; the tool never bypasses policy.
- **PowerShell executable missing:** install PowerShell 7 or set `powershell_executable` explicitly.
- **Module missing:** install the module named by the collector limitation and rerun only that category.
- **Exchange/Purview app-only failure:** set `exchange_organization` and verify certificate/RBAC setup.
- **SharePoint discovery failure:** pass `--sharepoint-url` through configuration.
- **Collector partial:** available evidence is retained; affected missing fields become `NOT_ASSESSED`.
- **HTTP 429:** Graph and Fabric clients respect service retry limits; reduce concurrency if throttling persists.
- **Token cache unavailable:** configure an OS keyring; otherwise caching remains memory-only.
- **Report regeneration:** use `report --input assessment.json` without contacting Microsoft 365.

Logs include collector IDs, status, exception types, and service request identifiers where available.
They deliberately omit authorization headers, tokens, response bodies, secrets, passwords, and keys.
