from types import SimpleNamespace

from security_ner import Entity

from secomlint.informativeness import Informativeness
from secomlint.section import Body, Metadata


def _message(*sections):
    return SimpleNamespace(sections=list(sections))


def _body(entities):
    return Body(lines=["some body text"], entities=entities)


def _meta(tag, entities):
    return Metadata(lines=f"{tag}: x", tag=tag, entities=entities)


def test_body_secwords_are_collected():
    body = _body([Entity("overflow", "SECWORD"), Entity("xss", "SECWORD"), Entity("ip", "URL")])
    info = Informativeness(_message(body))

    info.check_body()

    assert info.body_secwords == {"overflow", "xss"}


def test_no_body_does_not_raise():
    meta = _meta("weakness", [Entity("cwe-79", "CWEID")])
    info = Informativeness(_message(meta))  # no Body section

    result = info.evaluate()

    assert info.body == None
    assert result["body_secwords"] == []


def test_full_triage_is_high():
    sections = _message(
        _body([Entity("overflow", "SECWORD")]),
        _meta("weakness", [Entity("cwe-79", "CWEID")]),
        _meta("severity", [Entity("high", "SEVERITY")]),
        _meta("detection", [Entity("code review", "DETECTION")]),
    )
    info = Informativeness(sections)

    result = info.evaluate()

    assert result["detection"] is True
    assert result["assessment"] is True
    assert result["prioritization"] is True
    assert result["level"] == "high"
    assert result["body_secwords"] == ["overflow"]


def test_partial_triage_levels():
    # Only weakness present -> assessment only -> 1 system -> "low".
    info = Informativeness(_message(_meta("weakness", [Entity("cwe-79", "CWEID")])))
    result = info.evaluate()
    assert (result["assessment"], result["detection"], result["prioritization"]) == (True, False, False)
    assert result["level"] == "low"


def test_no_triage_is_none():
    body = _body([Entity("overflow", "SECWORD")])
    info = Informativeness(_message(body))
    result = info.evaluate()
    assert result["level"] == "none"
    # Body can still be informative even when no triage system is supported.
    assert result["body_secwords"] == ["overflow"]
