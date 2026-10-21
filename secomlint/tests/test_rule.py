"""Unit tests for the compliance rules in secomlint.rule.

Each rule is exercised directly with hand-built sections and entities, so these
tests need neither the NER model nor the parser. Every rule is checked in both
its compliant and non-compliant paths.
"""

import pytest

from security_ner import Entity

from secomlint.rule import Rule
from secomlint.section import Header, Body, Metadata, Bugtracker


def _rule(name, value, wtype=1, tag=None):
    # Rule(name, active, wtype, value, section, tag)
    return Rule(name, True, wtype, value, None, tag=tag)


# --------------------------------------------------------------------------- #
# Header
# --------------------------------------------------------------------------- #

def test_header_max_length():
    short = Header(lines=["vuln-fix: short header"])
    long = Header(lines=["x" * 80])
    assert Rule.header_max_length(_rule("header_max_length", 50), short).is_compliant is True
    assert Rule.header_max_length(_rule("header_max_length", 50), long).is_compliant is False


def test_header_is_not_empty():
    assert Rule.header_is_not_empty(_rule("header_is_not_empty", 0), Header(lines=["text"])).is_compliant is True
    assert Rule.header_is_not_empty(_rule("header_is_not_empty", 0), Header(lines=[""])).is_compliant is False


def test_header_starts_with_type():
    ok = Header(lines=["vuln-fix: patch xss"])
    bad = Header(lines=["fix: patch xss"])
    # The type must be followed by a colon: "vuln-fixed ..." does not count.
    no_colon = Header(lines=["vuln-fixed something else"])
    assert Rule.header_starts_with_type(_rule("header_starts_with_type", "vuln-fix"), ok).is_compliant is True
    assert Rule.header_starts_with_type(_rule("header_starts_with_type", "vuln-fix"), bad).is_compliant is False
    assert Rule.header_starts_with_type(_rule("header_starts_with_type", "vuln-fix"), no_colon).is_compliant is False


def test_header_starts_with_type_escapes_regex_metachars():
    # A type value with a regex metachar must be matched literally.
    rule = _rule("header_starts_with_type", "v.fix")
    assert Rule.header_starts_with_type(rule, Header(lines=["v.fix: x"])).is_compliant is True
    # Without escaping, '.' would match any char and accept "vxfix:".
    assert Rule.header_starts_with_type(rule, Header(lines=["vxfix: x"])).is_compliant is False


def test_header_ends_with_vuln_id():
    # value 'entity' makes the rule look for a VULNID entity at the end.
    at_end = Header(lines=["vuln-fix: patch (cve-2024-1234)"],
                    entities=[Entity("cve-2024-1234", "VULNID")])
    assert Rule.header_ends_with_vuln_id(_rule("header_ends_with_vuln_id", "entity"), at_end).is_compliant is True

    no_id = Header(lines=["vuln-fix: patch"], entities=[])
    assert Rule.header_ends_with_vuln_id(_rule("header_ends_with_vuln_id", "entity"), no_id).is_compliant is False

    not_at_end = Header(lines=["vuln-fix: cve-2024-1234 patch"],
                        entities=[Entity("cve-2024-1234", "VULNID")])
    assert Rule.header_ends_with_vuln_id(_rule("header_ends_with_vuln_id", "entity"), not_at_end).is_compliant is False


# --------------------------------------------------------------------------- #
# Body
# --------------------------------------------------------------------------- #

def test_body_max_length_counts_words_not_chars():
    ok = Body(lines=["a short body"])
    long = Body(lines=["word " * 80])
    assert Rule.body_max_length(_rule("body_max_length", 75), ok).is_compliant is True
    assert Rule.body_max_length(_rule("body_max_length", 75), long).is_compliant is False
    # Regression: many characters but few words must stay within the limit.
    many_chars = Body(lines=["supercalifragilisticexpialidocious " * 5])  # 5 words, ~180 chars
    assert Rule.body_max_length(_rule("body_max_length", 75), many_chars).is_compliant is True


def test_body_is_not_empty():
    assert Rule.body_is_not_empty(_rule("body_is_not_empty", 0), Body(lines=["text"])).is_compliant is True
    assert Rule.body_is_not_empty(_rule("body_is_not_empty", 0), Body(lines=[""])).is_compliant is False


def test_body_has_three_paragraphs():
    three = Body(lines=["what", "why", "how"])
    four = Body(lines=["what", "why", "how", "and more"])
    two = Body(lines=["what", "why"])
    empty = Body(lines=[])
    assert Rule.body_has_three_paragraphs(_rule("body_has_three_paragraphs", None), three).is_compliant is True
    # At least three content lines pass (not exactly three), so longer bodies
    # are no longer falsely rejected.
    assert Rule.body_has_three_paragraphs(_rule("body_has_three_paragraphs", None), four).is_compliant is True
    assert Rule.body_has_three_paragraphs(_rule("body_has_three_paragraphs", None), two).is_compliant is False
    assert Rule.body_has_three_paragraphs(_rule("body_has_three_paragraphs", None), empty).is_compliant is False


# --------------------------------------------------------------------------- #
# Metadata (entity-backed rules)
# --------------------------------------------------------------------------- #

# The entity-label metadata rules now share the generic `entity_label` checker,
# parametrized by (tag, required NER label). (name, tag, label, example text)
META_CASES = [
    ("metadata_has_weakness", "weakness", "CWEID", "cwe-79"),
    ("metadata_has_severity", "severity", "SEVERITY", "high"),
    ("metadata_has_detection", "detection", "DETECTION", "code review"),
    ("metadata_has_report", "report", "URL", "https://example.com/report/1"),
    ("metadata_has_introduced_in", "introduced_in", "SHA", "a1b2c3d4e5f6"),
]


def _entity_rule(name, tag, label):
    return Rule(name, True, 1, "entity", None, tag=tag,
                check="entity_label", requires_label=label, subject=tag)


@pytest.mark.parametrize("name,tag,label,text", META_CASES)
def test_metadata_rule_present(name, tag, label, text):
    sec = Metadata(lines=f"{tag}: {text}", tag=tag, entities=[Entity(text, label)])
    result = Rule.entity_label(_entity_rule(name, tag, label), sec)
    assert result.is_compliant is True
    assert result.rule_name == name   # the Result still carries the rule's name


@pytest.mark.parametrize("name,tag,label,text", META_CASES)
def test_metadata_rule_missing_entity(name, tag, label, text):
    sec = Metadata(lines=f"{tag}:", tag=tag, entities=[])
    assert Rule.entity_label(_entity_rule(name, tag, label), sec).is_compliant is False


def test_metadata_has_cvss():
    present = Metadata(lines="cvss: 7.5", tag="cvss", entities=[])
    vector = Metadata(lines="cvss: cvss:3.1/av:n/ac:l", tag="cvss", entities=[])
    garbage = Metadata(lines="cvss: not a valid score", tag="cvss", entities=[])
    missing = Metadata(lines=None, tag="cvss", entities=[])
    assert Rule.metadata_has_cvss(_rule("metadata_has_cvss", "entity", tag="cvss"), present).is_compliant is True
    assert Rule.metadata_has_cvss(_rule("metadata_has_cvss", "entity", tag="cvss"), vector).is_compliant is True
    assert Rule.metadata_has_cvss(_rule("metadata_has_cvss", "entity", tag="cvss"), garbage).is_compliant is False
    assert Rule.metadata_has_cvss(_rule("metadata_has_cvss", "entity", tag="cvss"), missing).is_compliant is False


# --------------------------------------------------------------------------- #
# Bugtracker
# --------------------------------------------------------------------------- #

def test_bugtracker_reference_bugtracker_url():
    sec = Bugtracker(lines=["bug-tracker: https://example.com/bugs/1"], tag="reference",
                     entities=[Entity("https://example.com/bugs/1", "URL")])
    assert Rule.bugtracker_has_reference(_rule("bugtracker_has_reference", "entity", tag="reference"), sec).is_compliant is True


def test_bugtracker_reference_resolves_issue():
    sec = Bugtracker(lines=["resolves: #42"], tag="reference", entities=[Entity("#42", "ISSUE")])
    assert Rule.bugtracker_has_reference(_rule("bugtracker_has_reference", "entity", tag="reference"), sec).is_compliant is True


def test_bugtracker_reference_fixes_accepts_commit_sha():
    # The parser accepts the 'fixes' tag; a "Fixes: <sha>" reference must count.
    sec = Bugtracker(lines=["fixes: f15f05b0a5de"], tag="reference",
                     entities=[Entity("f15f05b0a5de", "SHA")])
    assert Rule.bugtracker_has_reference(_rule("bugtracker_has_reference", "entity", tag="reference"), sec).is_compliant is True


def test_bugtracker_reference_missing_url():
    sec = Bugtracker(lines=["bug-tracker: no url here"], tag="reference", entities=[])
    assert Rule.bugtracker_has_reference(_rule("bugtracker_has_reference", "entity", tag="reference"), sec).is_compliant is False
