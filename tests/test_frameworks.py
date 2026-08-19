from pathlib import Path

import pytest

from m365_assessor.benchmarks.catalog import FrameworkCatalog
from m365_assessor.collectors.registry import default_registry
from m365_assessor.core.scanner import _selected_rules
from m365_assessor.rules.loader import default_rule_registry


def test_catalog_supports_multiple_framework_selection() -> None:
    selected = FrameworkCatalog.load().select(["cis-m365-7.0.0", "nist-csf-2.0"])
    assert [item.version for item in selected] == ["7.0.0", "2.0"]
    assert [item.mapping_key for item in selected] == ["CIS", "NIST"]


def test_unknown_framework_fails_closed() -> None:
    with pytest.raises(ValueError, match="Unknown"):
        FrameworkCatalog.load().select(["made-up"])


def test_framework_selection_filters_reported_mappings() -> None:
    catalog = FrameworkCatalog.load()
    selected = _selected_rules(
        default_rule_registry().all(),
        catalog.select(["cis-m365-7.0.0"]),
        {item.metadata.id for item in default_registry().all()},
    )
    assert len(selected) == 97
    assert all({mapping.framework for mapping in rule.benchmarks} == {"CIS"} for rule in selected)


def test_external_framework_directory_is_merged_with_builtins(tmp_path: Path) -> None:
    (tmp_path / "client.yaml").write_text(
        """id: client-1
name: Client Baseline
provider: Client
version: "1"
kind: custom
mapping_key: CLIENT
description: Test baseline
reference_url: https://example.invalid
mapping_status: client_managed
""",
        encoding="utf-8",
    )
    catalog = FrameworkCatalog.load(tmp_path)
    assert [item.id for item in catalog.select(["cis-m365-7.0.0", "client-1"])] == [
        "cis-m365-7.0.0",
        "client-1",
    ]
