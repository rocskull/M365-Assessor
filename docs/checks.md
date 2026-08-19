# Checks and rules

The built-in pack contains 97 production checks:

- Entra ID: 24
- Exchange Online and Defender: 28
- Microsoft Teams: 16
- SharePoint Online and OneDrive: 12
- Microsoft Purview: 5
- Microsoft Fabric: 12

Checks are safe YAML interpreted by a closed deterministic evaluator. YAML cannot execute Python or
PowerShell. Supported operators include scalar comparisons, set membership, nested all/any/not,
collection quantifiers, and application-credential restriction validation.

Each production check includes a collector dependency, deterministic evaluation, evidence fields,
severity, rationale, remediation, references, CIS mapping, NIST mapping, and unit coverage. Missing
permissions or evidence return `NOT_ASSESSED`; evaluator defects return `ERROR`.

Place additional YAML rule packs in the configured `rule_directory`. Each external framework mapping
uses the framework's stable `mapping_key`; duplicate check IDs are rejected.
