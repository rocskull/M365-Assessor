# Benchmarks and compliance frameworks

Built-in framework definitions:

- CIS Microsoft 365 Foundations Benchmark 7.0.0
- NIST Cybersecurity Framework 2.0

The built-in 97-control pack maps each implemented check to both frameworks. It does not claim full
automation of every CIS recommendation, and NIST mappings are assessor-defined outcome mappings rather
than certification.

```powershell
m365-assessor scan --tenant <tenant-id> --framework cis-m365-7.0.0
m365-assessor scan --tenant <tenant-id> --framework cis-m365-7.0.0 --framework nist-csf-2.0
```

For a client framework, copy `config/frameworks/custom.example.yaml` into an external directory, give
it a stable `mapping_key`, create rules with matching benchmark entries in an external `rule_directory`,
and configure both directories. Built-ins and external packs are merged; duplicate IDs fail closed.

The attached CIS PDF was used to identify control IDs and technical thresholds. Descriptions,
rationales, evaluations, and remediation guidance were independently authored, and the PDF is not
redistributed.
