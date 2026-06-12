from collections import Counter

from secomlint.message import Message
import messages


def norm_message(msg):
    return msg.value.lower().split('\n')


def section_counts(message):
    """Count parsed sections by type, e.g. {'Header': 1, 'Metadata': 6, ...}."""
    return Counter(type(s).__name__ for s in message.sections)


# The parser guarantees a fixed set of Metadata (6) and Contact (3) sections:
# every known tag is either present or created as a placeholder. A Header is
# always emitted; Body and Bugtracker only appear when present in the message.

def test_get_sections_all():
    # Full message: header + body + metadata/contacts (present + placeholders) + bugtracker.
    lines = norm_message(messages.Message.MSG1)
    message = Message(lines)
    message.parse()
    assert section_counts(message) == {
        "Header": 1, "Body": 1, "Metadata": 6, "Contact": 3, "Bugtracker": 1,
    }
    assert len(message.sections) == 12


def test_get_sections_no_body():
    # No body: identical to MSG1 minus the single Body section.
    lines = norm_message(messages.Message.MSG2)
    message = Message(lines)
    message.parse()
    assert section_counts(message) == {
        "Header": 1, "Metadata": 6, "Contact": 3, "Bugtracker": 1,
    }
    assert len(message.sections) == 11


def test_get_sections_no_body_and_no_metadata():
    # No body and no metadata present: the 6 metadata tags become placeholders.
    lines = norm_message(messages.Message.MSG3)
    message = Message(lines)
    message.parse()
    assert section_counts(message) == {
        "Header": 1, "Metadata": 6, "Contact": 3, "Bugtracker": 1,
    }
    assert len(message.sections) == 11
