"""Tests for the Compliance orchestration: scoring and result ordering.

These drive Compliance with hand-built sections (no NER, no parser), relying on
the real rules.yml so the rule set and section/tag wiring are the production ones.
"""

from types import SimpleNamespace

import pytest
from security_ner import Entity

from secomlint.compliance import Compliance
from secomlint.config import Config
from secomlint.ruler import Ruler
from secomlint.section import Metadata


def _compliance():
    return Compliance(Config())


def test_calculate_score_no_rules_is_zero():
    comp = _compliance()
    comp.ruler.rules = []
    comp.results = []
    comp.calculate_score()
    assert comp.score == 0.0


def test_calculate_score_is_fraction_of_total_rules():
    comp = _compliance()
    total = len(comp.ruler.rules)
    comp.results = [
        SimpleNamespace(is_compliant=True, type=1),
        SimpleNamespace(is_compliant=True, type=0),
        SimpleNamespace(is_compliant=False, type=0),
    ]
    comp.calculate_score()
    assert comp.score == pytest.approx(2 / total)


def test_check_counts_and_orders_errors_before_warnings_before_compliant():
    # severity -> error (type 1, no entity), detection -> warning (type 0, no
    # entity), cvss with lines -> compliant (type 0).
    message = SimpleNamespace(sections=[
        Metadata(lines="severity:", tag="severity", entities=[]),
        Metadata(lines="detection:", tag="detection", entities=[]),
        Metadata(lines="cvss: 7.5", tag="cvss", entities=[]),
    ])

    comp = _compliance()
    comp.check(message)

    assert (comp.errors, comp.warnings, comp.compliant) == (1, 1, 1)

    ordered = [(r.is_compliant, r.type) for r in comp.results]
    assert ordered[0] == (False, 1)      # error first
    assert ordered[1] == (False, 0)      # then warning
    assert ordered[-1][0] is True        # compliant last


def test_valid_and_completeness_split_required_from_recommended():
    # severity (error, no entity) -> required fails -> not valid.
    # detection (warning, no entity) -> recommended fails.
    # cvss (warning, has value) -> recommended passes.
    message = SimpleNamespace(sections=[
        Metadata(lines="severity:", tag="severity", entities=[]),
        Metadata(lines="detection:", tag="detection", entities=[]),
        Metadata(lines="cvss: 7.5", tag="cvss", entities=[]),
    ])
    comp = _compliance()
    comp.check(message)
    comp.calculate_score()

    assert comp.required_total == 1 and comp.required_passed == 0
    assert comp.valid is False                       # a required rule failed
    assert comp.recommended_total == 2 and comp.recommended_passed == 1
    assert comp.completeness == pytest.approx(0.5)


def test_valid_true_when_all_required_pass():
    # severity satisfied (required passes); detection missing (only recommended).
    message = SimpleNamespace(sections=[
        Metadata(lines="severity: high", tag="severity",
                 entities=[Entity("high", "SEVERITY")]),
        Metadata(lines="detection:", tag="detection", entities=[]),
    ])
    comp = _compliance()
    comp.check(message)
    comp.calculate_score()
    assert comp.required_passed == comp.required_total
    assert comp.valid is True
    assert comp.completeness < 1.0   # detection recommended rule still failing


def test_shared_ruler_is_reused_across_instances():
    cfg = Config()
    ruler = Ruler(Config(path=cfg.rules_config_path))
    c1 = Compliance(cfg, ruler=ruler)
    c2 = Compliance(cfg, ruler=ruler)
    # Same ruler object reused (no rebuild), but independent per-message state.
    assert c1.ruler is ruler and c2.ruler is ruler
    c1.check(SimpleNamespace(sections=[
        Metadata(lines="severity: high", tag="severity",
                 entities=[Entity("high", "SEVERITY")]),
    ]))
    assert c1.results and c2.results == []


def test_score_denominator_excludes_inactive_rules():
    comp = _compliance()
    total = len(comp.ruler.rules)
    comp.ruler.rules[0].active = False          # disable one rule
    comp.results = [SimpleNamespace(is_compliant=True, type=1)]
    comp.calculate_score()
    assert comp.score == pytest.approx(1 / (total - 1))


def test_check_single_section_runs_only_its_rules():
    # A lone Metadata/severity section triggers exactly one rule.
    message = SimpleNamespace(sections=[
        Metadata(lines="severity: high", tag="severity", entities=[]),
    ])
    comp = _compliance()
    comp.check(message)
    assert len(comp.results) == 1
    assert comp.results[0].rule_name == "metadata_has_severity"
