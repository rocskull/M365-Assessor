# Architecture

```text
CLI / FastAPI
    -> validated configuration + framework selection
    -> MSAL / managed identity authentication
    -> token and runtime-service permission discovery
    -> bounded concurrent collector runner
       -> Microsoft Graph client
       -> read-only Microsoft service adapters
       -> optional cached snapshots
    -> normalized collector evidence
    -> deterministic versioned YAML rules
    -> coverage + permission analysis
    -> normalized assessment document
    -> JSON / HTML / CSV / XLSX / SQLAlchemy / evidence cache
```

Collectors gather facts and never decide compliance. Rules evaluate normalized facts and never call
tenant APIs. Framework mappings live in data files rather than Python evaluators. Reports consume the
normalized document and never authenticate.

The Graph client centrally owns TLS verification, authentication headers, timeouts, pagination,
throttling, bounded exponential backoff, and same-host next-link validation. Service adapters accept
only collector-owned static read commands and keep authentication material out of command-line
arguments and logs.

Collectors, rules, and frameworks have registries. Built-in and configured external rule/framework
directories are merged, with duplicate IDs rejected. SQLAlchemy isolates persistence so SQLite can
be replaced by PostgreSQL without changing the assessment engine.
