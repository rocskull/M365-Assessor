# Development

```powershell
python -m pip install -e ".[dev,security]"
pytest
ruff check .
mypy src
python -m build
pip-audit
m365-assessor sbom --output reports\m365-assessor-sbom.json
```

Tests mock Microsoft Graph and inject service snapshots; no live tenant is required. Optional
integration tests must use `M365_ASSESSOR_TENANT_ID` and `M365_ASSESSOR_CLIENT_ID` and skip when absent.

A check is complete only with evidence collection, deterministic evaluation, a unit case, remediation,
and applicable framework mappings. Keep collection, evaluation, mapping, presentation, and persistence
separate. Never copy third-party assessment-tool code or licensed benchmark prose.

Regenerate the synthetic 97-control sample with:

```powershell
python scripts\generate_sample.py
```
