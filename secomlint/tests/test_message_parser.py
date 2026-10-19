"""Parser tests for secomlint.message.Message.

A fake NER is injected so these tests exercise the sectioning, tag
normalization and placeholder logic without loading the real model.
"""

from secomlint.message import Message
from secomlint.section import Metadata, Contact, Bugtracker


class _FakeNer:
    """Stand-in for a security_ner model: returns no entities."""
    def extract(self, text):
        return []


def _parse(lines):
    message = Message(lines, ner=_FakeNer())
    message.parse()
    return message


def _by_type(message, name):
    return [s for s in message.sections if type(s).__name__ == name]


# --------------------------------------------------------------------------- #
# Tag normalization
# --------------------------------------------------------------------------- #

def test_match_metadata_normalizes_spaces_to_underscore():
    m = Message([], ner=_FakeNer())
    assert m._match_metadata("introduced in: a1b2c3") == "introduced_in"
    assert m._match_metadata("weakness: cwe-79") == "weakness"
    assert m._match_metadata("not a tag") is None


def test_match_contact_normalizes_hyphen_to_underscore():
    m = Message([], ner=_FakeNer())
    assert m._match_contact("reported-by: jane (jane@x.com)") == "reported_by"
    assert m._match_contact("co-authored-by: x") == "co_authored_by"
    assert m._match_contact("weakness: x") is None


# --------------------------------------------------------------------------- #
# Placeholders: all known metadata/contact tags always exist
# --------------------------------------------------------------------------- #

def test_header_only_message_fills_placeholders():
    message = _parse(["vuln-fix: just a header"])
    assert len(_by_type(message, "Header")) == 1
    assert len(_by_type(message, "Metadata")) == 6   # placeholders
    assert len(_by_type(message, "Contact")) == 3     # placeholders
    assert len(_by_type(message, "Body")) == 1        # placeholder
    assert len(_by_type(message, "Bugtracker")) == 1  # placeholder
    # Metadata/Contact placeholders carry no lines; Body/Bugtracker use an
    # empty list so the body rules can index section.lines safely.
    assert all(m.lines is None for m in _by_type(message, "Metadata"))
    assert _by_type(message, "Body")[0].lines == []
    assert _by_type(message, "Bugtracker")[0].lines == []


def test_present_metadata_is_kept_and_not_duplicated():
    message = _parse([
        "vuln-fix: fix",
        "",
        "weakness: cwe-79",
        "introduced in: a1b2c3d4",
    ])
    metas = {m.tag: m for m in _by_type(message, "Metadata")}
    # Still exactly the 6 known tags, no duplicates.
    assert len(metas) == 6
    # Present ones keep their line; absent ones are placeholders (lines is None).
    assert metas["weakness"].lines is not None
    assert metas["introduced_in"].lines is not None
    assert metas["severity"].lines is None


def test_present_contact_tag_is_normalized():
    message = _parse([
        "vuln-fix: fix",
        "",
        "reported-by: jane (jane@example.com)",
    ])
    contacts = {c.tag: c for c in _by_type(message, "Contact")}
    assert set(contacts) == {"reported_by", "signed_off_by", "co_authored_by"}
    assert contacts["reported_by"].lines is not None
    assert contacts["signed_off_by"].lines is None  # placeholder


# --------------------------------------------------------------------------- #
# Bugtracker accumulation
# --------------------------------------------------------------------------- #

def test_bugtracker_lines_accumulate_into_one_section():
    message = _parse([
        "vuln-fix: fix",
        "",
        "bug-tracker: https://example.com/1",
        "see also: #2",
    ])
    bugtrackers = _by_type(message, "Bugtracker")
    assert len(bugtrackers) == 1
    assert len(bugtrackers[0].lines) == 2
