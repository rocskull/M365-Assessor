# Microsoft 365 Security Assessor

`m365-assessor` is an independently implemented, read-only Microsoft 365 security assessment tool.
It authenticates with Microsoft identity, collects normalized tenant evidence through Microsoft Graph
and Microsoft-supported administrative interfaces, evaluates versioned controls, produces a Coverage
& Permission Report, and exports JSON, HTML, CSV, and Excel reports.

The implementation contains no Monkey365 source, text, or internal architecture. The supplied CIS
benchmark is used only as a licensed reference for control identity and expected configuration; all
tool wording and code are independently written.

## Current release

Version 1.2.0 includes:

- Interactive, device-code, secret-based service principal, certificate, and managed-identity auth
- Secure MSAL token caching through the operating-system keyring with a memory-only fallback
- Microsoft Graph pagination, `429`/`Retry-After` handling, bounded backoff, and safe next links
- Entra, Exchange/Defender, Teams, SharePoint/OneDrive, Purview, and optional Fabric collectors
- 97 deterministic checks mapped to CIS Microsoft 365 Foundations 7.0.0 and NIST CSF 2.0
- External framework and rule directories for client-specific compliance baselines
- Permission and runtime-service coverage with explicit reasons for every unavailable area
- JSON, self-contained HTML, CSV, and eight-sheet Excel reports
- SQLite persistence with a PostgreSQL-compatible SQLAlchemy architecture
- Evidence caching, offline service snapshots, a FastAPI API, structured redacted logs, and SBOM output

The 97-control pack is a supported subset, not a claim that every recommendation in the CIS benchmark
is automated. Manual recommendations and controls without a reliable supported read interface remain
outside the scored pack and are documented as limitations.

## Quick start

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item config\config.example.yaml config\config.yaml
m365-assessor benchmarks list
m365-assessor scan --tenant <tenant-id> --dry-run
m365-assessor scan --tenant <tenant-id> --framework 1 --client-name Contoso -O D:\Assessments --cache
```

For interactive or device-code authentication, `--tenant` may be omitted. Microsoft account
selection opens first; the tool discovers and displays the organizational tenant and requires
confirmation before collection starts. Use `--yes` only for an intentionally non-interactive
discovery run. App-only authentication continues to require an explicit tenant.

A complete scan asks for a client name and output root when they are not supplied, then creates a
folder such as `Contoso-m365-assessment-20260819-164510`. Report filenames use the same client and
timestamp stem. `-O` is the short form of `--output`; `-C` is the short form of `--client-name`.

Frameworks are displayed with selection numbers. Enter `1`, `2`, or a comma-separated selection such
as `1,2`; framework IDs remain supported for automation. Non-interactive execution defaults visibly
to CIS 7.0.0 when no framework is configured.

## Commands

```text
m365-assessor auth login
m365-assessor tenant info
m365-assessor permissions
m365-assessor collectors list
m365-assessor checks list
m365-assessor benchmarks list
m365-assessor scan
m365-assessor report --input assessment.json
m365-assessor export --input assessment.json --format html,json,csv,xlsx
m365-assessor serve
m365-assessor sbom
```

See [installation](docs/installation.md), [authentication](docs/authentication.md), the
[organization-owned app-registration guide](docs/organization-owned-app-registration.md),
[permissions](docs/permissions.md), [architecture](docs/architecture.md), and
[reporting](docs/reporting.md). Synthetic artifacts are in
[`examples/sample-report`](examples/sample-report).

## Quality gate

```powershell
pytest
ruff check .
mypy src
python -m build
```

Tests use mocked Microsoft Graph and service snapshots. They do not require a real tenant.
