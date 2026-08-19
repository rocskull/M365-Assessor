# Installation

Requirements:

- Python 3.12+
- Microsoft Entra application registration
- OS credential vault supported by Python `keyring`
- PowerShell 7 for non-Graph collectors
- Current `ExchangeOnlineManagement`, `MicrosoftTeams`, `PnP.PowerShell`, and `Az.Accounts` modules

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module MicrosoftTeams -Scope CurrentUser
Install-Module PnP.PowerShell -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser
Copy-Item config\config.example.yaml config\config.yaml
m365-assessor --help
```

Use PostgreSQL by replacing `database_url` with a PostgreSQL SQLAlchemy URL and installing the chosen
driver. Pin resolved dependencies for production. Run `pip-audit` from the security extra and generate
an offline SBOM with `m365-assessor sbom`.

Never commit `.env`, reports, tenant evidence, private keys, certificate bundles, or local databases.
