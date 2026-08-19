# Reporting

Every scan produces four formats from the same normalized assessment document. The interactive CLI
asks for a client name and output root unless they are supplied with `--client-name`/`-C` and
`--output`/`-O`. It creates a folder named
`<client>-m365-assessment-<YYYYMMDD-HHMMSS>` and applies the same stem to report filenames:

- `<stem>.json`: machine-readable assessment, evidence, coverage, findings, and mappings
- `<stem>.html`: self-contained dashboard with search, filters, coverage, evidence, and remediation
- `<stem>.xlsx`: Executive Summary, Finding Register, Good Controls, Not Assessed, Permission
  Coverage, Framework Mapping, Raw Evidence, and Methodology sheets
- `<stem>-findings.csv`: one row per finding/resource with CIS fields and recommendation

The Excel workbook includes filters, freeze panes, tables, severity formatting, hyperlinks, readable
widths, and a severity chart. The HTML renderer enables Jinja autoescaping and serializes evidence
safely. Report models deliberately exclude tokens and credentials.

Pass percentage uses only PASS, FAIL, and WARNING controls. `NOT_ASSESSED`, `NOT_APPLICABLE`, and
`ERROR` do not enter the pass denominator. Coverage percentage is reported separately.

```powershell
m365-assessor report --input .\reports\assessment.json --output .\reports
m365-assessor export --input .\reports\assessment.json --format html,xlsx
```

See [`examples/sample-report`](../examples/sample-report) for a synthetic 97-control report.
