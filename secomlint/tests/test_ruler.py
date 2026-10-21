"""Tests for secomlint.ruler.Ruler: rule construction and section filtering."""

from types import SimpleNamespace

import pytest

from secomlint.ruler import Ruler
from secomlint.config import Config
from secomlint.section import Header, Metadata


def _ruler():
    return Ruler(Config())


def test_builds_all_rules_from_config():
    assert len(_ruler().rules) == 17


def test_header_rules_have_no_tag():
    header_rules = _ruler().get_section_rules(Header(), tag=None)
    assert {r.name for r in header_rules} == {
        "header_max_length",
        "header_is_not_empty",
        "header_starts_with_type",
        "header_ends_with_vuln_id",
    }


def test_rule_without_value_defaults_to_entity():
    rule = next(r for r in _ruler().rules if r.name == "header_ends_with_vuln_id")
    assert rule.value == "entity"


def test_metadata_tag_is_derived_from_rule_name():
    rule = next(r for r in _ruler().rules if r.name == "metadata_has_introduced_in")
    assert rule.tag == "introduced_in"


def test_get_section_rules_filters_by_type_and_tag():
    ruler = _ruler()
    rules = ruler.get_section_rules(Metadata(tag="severity"), tag="severity")
    assert [r.name for r in rules] == ["metadata_has_severity"]
    # A different tag on the same section type returns a different single rule.
    rules = ruler.get_section_rules(Metadata(tag="cvss"), tag="cvss")
    assert [r.name for r in rules] == ["metadata_has_cvss"]


def test_unknown_handler_raises_at_load_time():
    bad = SimpleNamespace(default_rules={
        "metadata_has_bogus": {"active": True, "type": 0, "check": "no_such_checker"},
    })
    with pytest.raises(ValueError, match="unknown handler"):
        Ruler(bad)


def test_rule_name_without_method_raises_at_load_time():
    bad = SimpleNamespace(default_rules={
        "header_not_a_real_rule": {"active": True, "type": 0},
    })
    with pytest.raises(ValueError, match="unknown handler"):
        Ruler(bad)


def test_unknown_section_prefix_raises_at_load_time():
    bad = SimpleNamespace(default_rules={
        "bogussection_has_x": {"active": True, "type": 0},
    })
    with pytest.raises(ValueError, match="no known section"):
        Ruler(bad)
