"""Rules for the Contact section: reported-by, signed-off-by, co-authored-by.

Each rule must behave the same way: compliant only when the tag is present
*and* an EMAIL entity was extracted; not compliant when the email is missing or
the whole section is absent. The Result slug must match the method name so the
documentation links in the report point to the right anchor.
"""

from security_ner import Entity

from secomlint.rule import Rule
from secomlint.section import Contact


# (method name, section tag, config value label)
CASES = [
    ("contact_has_reported_by", "reported_by", "reported-by"),
    ("contact_has_signed_off_by", "signed_off_by", "signed-off-by"),
    ("contact_has_co_authored_by", "co_authored_by", "co-authored-by"),
]


def _rule(name, tag, value, wtype=0):
    # Rule(name, active, wtype, value, section, tag, check)
    return Rule(name, True, wtype, value, None, tag=tag, check="contact_email")


def _contact(tag, entities):
    return Contact(lines=f"{tag}: someone", tag=tag, entities=entities)


def _run(meth, tag, value, entities):
    # All three contact rules share the generic contact_email checker.
    return Rule.contact_email(_rule(meth, tag, value), _contact(tag, entities))


def test_contact_with_email_is_compliant():
    for meth, tag, value in CASES:
        result = _run(meth, tag, value, [Entity("jane@example.com", "EMAIL")])
        assert result.is_compliant is True, f"{meth} should pass when email present"


def test_contact_tag_present_without_email_is_not_compliant():
    # Regression: co-authored-by used to return compliant=True with no email,
    # unlike its siblings, inflating the compliance score.
    for meth, tag, value in CASES:
        result = _run(meth, tag, value, [])
        assert result.is_compliant is False, f"{meth} should fail when email missing"


def test_result_slug_matches_method_name():
    # Result.rule_name drives the docs anchor; it must equal the method name.
    for meth, tag, value in CASES:
        result = _run(meth, tag, value, [Entity("jane@example.com", "EMAIL")])
        assert result.rule_name == meth, f"{meth} -> {result.rule_name}"


def test_missing_email_severity_follows_rule_type():
    # signed-off-by is a type-1 (error) rule: a present tag without an email is
    # an error, not a downgraded warning.
    sec = _contact("signed_off_by", [])
    rule = Rule("contact_has_signed_off_by", True, 1, "signed-off-by", None,
                tag="signed_off_by", check="contact_email")
    result = Rule.contact_email(rule, sec)
    assert result.is_compliant is False
    assert result.type == 1
