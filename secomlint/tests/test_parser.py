from collections import Counter

from secomlint.message import Message
import messages


def norm_message(msg):
    return msg.value.lower().split('\n')


def section_counts(message):
    """Count parsed sections by type, e.g. {'Header': 1, 'Metadata': 6, ...}."""
    return Counter(type(s).__name__ for s in message.sections)


# The parser guarantees a fixed set of sections: a Header, 6 Metadata, 3
# Contact, 1 Body and 1 Bugtracker. Every one is either present in the message
# or created as an empty placeholder, so a parsed message always has 12
# sections and every rule is always evaluated and reported.

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
    # No body in the text: a Body placeholder is created so the count still holds.
    lines = norm_message(messages.Message.MSG2)
    message = Message(lines)
    message.parse()
    assert section_counts(message) == {
        "Header": 1, "Body": 1, "Metadata": 6, "Contact": 3, "Bugtracker": 1,
    }
    assert len(message.sections) == 12


def test_get_sections_no_body_and_no_metadata():
    # No body and no metadata present: both become placeholders (Body x1, Metadata x6).
    lines = norm_message(messages.Message.MSG3)
    message = Message(lines)
    message.parse()
    assert section_counts(message) == {
        "Header": 1, "Body": 1, "Metadata": 6, "Contact": 3, "Bugtracker": 1,
    }
    assert len(message.sections) == 12
