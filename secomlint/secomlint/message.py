import re
from typing import List, Optional, Iterator, Union

from secomlint.section import Header, Body, Metadata, Contact, Bugtracker
from secomlint.tags import TAGS, CONTACT, METADATA, BUG_TRACKER

from security_ner import load


# Precompile regex for performance and clarity
BODY_PATTERN = re.compile(rf"^(?!{'|'.join(TAGS)}(:)?.*$).*")
METADATA_PATTERN = re.compile(rf"^({'|'.join(METADATA)}):")
CONTACT_PATTERN = re.compile(rf"^({'|'.join(CONTACT)}):")
BUGTRACKER_PATTERN = re.compile(rf"^({'|'.join(BUG_TRACKER)})(:)?")


class Message:
    """
    Represents a parsed message with sections such as header, body, metadata,
    contacts, and bugtracker info.
    """

    def __init__(self, lines: List[str], ner=None) -> None:
        """
        Initialize the Message object with the raw lines of text.

        :param lines: A list of raw lines (strings) that comprise the message.
        :param ner: A security_ner model. Defaults to the shared (cached)
            "commits" model, so constructing many Messages does not reload it.
        """
        self.raw_text: List[str] = lines
        # Make a shallow copy to avoid accidental in-place modifications.
        self.text: List[str] = lines[:]
        self.sections: List[Union[Header, Body, Metadata, Contact, Bugtracker]] = []
        self._ner = ner or load("commits")

    def _entities(self, lines: List[str]):
        """Run the NER over the given lines and return a list of Entity objects."""
        return self._ner.extract("\n".join(lines))

    def parse(self) -> None:
        """
        Parse the message lines into structured sections (header, body,
        metadata, contacts, bugtracker, etc.).
        """
        chunks = list(self._split_into_sections(self.text))
        # We may store lines for a 'bugtracker' section in progress
        bugtracker_section: Optional[Bugtracker] = None

        for i, lines_chunk in enumerate(chunks):
            # Skip empty chunks
            if not lines_chunk:
                continue
            if i == 0 and len(lines_chunk) == 1:
                self.sections.append(
                    Header(lines=lines_chunk, entities=self._entities(lines_chunk))
                )
                continue

            # Check if the chunk is recognized as a body
            if i == 1 and self._is_body_section(lines_chunk):
                self.sections.append(
                    Body(lines=lines_chunk, entities=self._entities(lines_chunk))
                )
                continue

            # Otherwise, parse the chunk line by line (Metadata, Contact, Bugtracker, etc.)
            for line in lines_chunk:
                # Try matching each known pattern. The first match wins.
                metadata_tag = self._match_metadata(line)
                if metadata_tag:
                    self.sections.append(
                        Metadata(
                            lines=line,
                            tag=metadata_tag,
                            entities=self._entities([line])
                        )
                    )
                    continue

                contact_tag = self._match_contact(line)
                if contact_tag:
                    self.sections.append(
                        Contact(
                            lines=line,
                            tag=contact_tag,
                            entities=self._entities([line])
                        )
                    )
                    continue

                if self._is_bugtracker_line(line):
                    if bugtracker_section:
                        bugtracker_section.append_line(line)
                    else:
                        bugtracker_section = Bugtracker(
                            lines=[line],
                            tag="reference",
                            entities=self._entities([line])
                        )
                    continue
            # If a bugtracker section was created or appended, finalize it for this chunk
            if bugtracker_section:
                self.sections.append(bugtracker_section)
                # Reset if only one Bugtracker section is allowed; if you expect multiple, adjust accordingly
                bugtracker_section = None

        # Ensure all metadata/contact tags exist (i.e., create placeholders if missing)
        self._ensure_all_metadata_exists()
        self._ensure_all_contacts_exist()

    def _split_into_sections(self, lines: List[str]) -> Iterator[List[str]]:
        """
        Split the message lines into three main sections:
        1. Header (first line)
        2. Body (text between header and general data)
        3. General data (metadata, contact, bugtracker information)

        :param lines: The full list of lines for this message.
        :yield: Lists of lines belonging to each section.
        """
        
        if not lines: return

        # Header is always the first non-empty line
        header = []
        body = []
        general_data = []
        
        # Process lines
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # If we haven't found the header yet, this is it
            if not header:
                header = [line]
                continue
                
            # Check if this line starts with any of the special tags
            if (METADATA_PATTERN.search(line) or 
                CONTACT_PATTERN.search(line) or 
                BUGTRACKER_PATTERN.search(line)):
                general_data.append(line)
            else:
                # If we haven't seen any general data yet, this is body
                if not general_data:
                    body.append(line)
                else:
                    # Once we've seen general data, everything else goes there
                    general_data.append(line)

        # Yield sections in order
        if header:
            yield header
        if body:
            yield body
        if general_data:
            yield general_data

    def _is_body_section(self, lines_chunk: List[str]) -> bool:
        """
        Determine if a list of lines should be considered a body section.

        :param lines_chunk: The lines forming the current chunk.
        :return: True if the chunk is recognized as a body; otherwise False.
        """
        # Count lines that do NOT match recognized tags
        non_tag_count = sum(1 for line in lines_chunk if BODY_PATTERN.search(line))
        return len(lines_chunk) > 0 and non_tag_count > 0

    def _match_metadata(self, line: str) -> Optional[str]:
        """
        Check if a line matches one of the metadata tags. If so, return the normalized tag.

        :param line: A single line of text.
        :return: The normalized metadata tag (e.g., "some_tag") if matched; otherwise None.
        """
        match = METADATA_PATTERN.search(line)
        if match:
            # For example, if the line is "Key: value", 'Key:' would be captured
            raw_tag = match.group(0).replace(":", "").strip()
            return raw_tag.replace(" ", "_")
        return None

    def _match_contact(self, line: str) -> Optional[str]:
        """
        Check if a line matches one of the contact tags. If so, return the normalized tag.

        :param line: A single line of text.
        :return: The normalized contact tag (e.g., "some_contact") if matched; otherwise None.
        """
        match = CONTACT_PATTERN.search(line)
        if match:
            raw_tag = match.group(0).replace(":", "").strip()
            return raw_tag.replace("-", "_")
        return None

    def _is_bugtracker_line(self, line: str) -> bool:
        """
        Check if a line matches the bugtracker pattern.

        :param line: A single line of text.
        :return: True if it matches bugtracker patterns; False otherwise.
        """
        return bool(BUGTRACKER_PATTERN.search(line))

    def _ensure_all_metadata_exists(self) -> None:
        """
        Ensure all known metadata tags are present. If missing, create placeholder sections.
        """
        existing_metadata = {
            section.tag.replace("_", " ")
            for section in self.sections
            if isinstance(section, Metadata)
        }
        for tag in METADATA:
            if tag not in existing_metadata:
                self.sections.append(
                    Metadata(lines=None, tag=tag.replace(" ", "_"), entities=None)
                )

    def _ensure_all_contacts_exist(self) -> None:
        """
        Ensure all known contact tags are present. If missing, create placeholder sections.
        """
        existing_contacts = {
            section.tag.replace("_", "-")
            for section in self.sections
            if isinstance(section, Contact)
        }
        for tag in CONTACT:
            if tag not in existing_contacts:
                self.sections.append(
                    Contact(lines=None, tag=tag.replace("-", "_"), entities=None)
                )

    def get_sections(self) -> List[Union[Header, Body, Metadata, Contact, Bugtracker]]:
        """
        Retrieve the parsed sections of this message.

        :return: A list of section objects in the order they were parsed or appended.
        """
        return self.sections

    def get_text(self) -> List[str]:
        """
        Retrieve the raw message lines.

        :return: A list of raw strings (lines) that were passed to this object.
        """
        return self.text
