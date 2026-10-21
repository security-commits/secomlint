import re

from security_ner import CommonLabel


class Result:
    def __init__(self, rule_name, result, wtype, wmessage) -> None:
        self.rule_name = rule_name
        self.is_compliant = result
        self.type = wtype
        self.message = wmessage
        # Plain documentation URL (used in JSON output) and the terminal
        # hyperlink that wraps it (used in the colored report).
        self.doc = f"https://security-commits.org/secomlint/#/secomlint-rules?id={self.rule_name.replace('_', '-')}"
        self.link = f"[\u001b]8;;{self.doc}\u001b\\{self.rule_name}\u001b]8;;\u001b\\]"


class Rule:
    def __init__(self, name, active, wtype, value, section, tag=None,
                 check=None, requires_label=None, subject=None) -> None:
        self.name = name
        self.active = active
        self.wtype = wtype
        self.value = value
        self.section = section
        self.tag = tag
        # Data-driven checks: `check` names a generic handler (e.g. "entity_label")
        # instead of a per-rule method; `requires_label`/`subject` parametrize it.
        self.check = check
        self.requires_label = requires_label
        self.subject = subject

    def header_max_length(self, section):
        section_text = ''.join(section.lines)
        if section.lines and len(section_text) <= self.value:
            return Result('header_max_length', True, self.wtype,
                           f'Header size is within the max length ({self.value} chars).')
        return Result('header_max_length', False, self.wtype,
                       f'Header has more than {self.value} chars.')

    def header_is_not_empty(self, section):
        section_text = ''.join(section.lines)
        if len(section_text) > self.value:
            return Result('header_is_not_empty', True, self.wtype,
                           'Header is not empty.')
        return Result('header_is_not_empty', False, self.wtype,
                       'Header is empty.')

    def header_starts_with_type(self, section):
        section_text = ''.join(section.lines)
        if re.search(rf"^{re.escape(self.value)}:", section_text):
            return Result('header_starts_with_type', True, self.wtype,
                           f'Header starts with {self.value} type')
        return Result('header_starts_with_type', False, self.wtype,
                       f'Header is missing the {self.value} type at the start.')

    def header_ends_with_vuln_id(self, section):
        def vuln_id_at_the_end(value, text):
            return re.search(rf".*{re.escape(value)}(\))?$", text)
        section_text = ''.join(section.lines)
        if self.value == 'entity':
            entities = section.entities
            if entities:
                vuln_id = [entity.text
                           for entity in entities if entity.label == CommonLabel.VULNID]
                if vuln_id:
                    if vuln_id_at_the_end(vuln_id[0].lower(), section_text):
                        return Result('header_ends_with_vuln_id', True, self.wtype,
                                       'Header ends with vulnerability ID.')
        else:
            if vuln_id_at_the_end(self.value.lower(), section_text):
                return Result('header_ends_with_vuln_id', True, self.wtype,
                               'Header ends with vulnerability ID')
        return Result('header_ends_with_vuln_id', False, self.wtype,
                       'Header is missing the vulnerability ID at the end.')

    def body_max_length(self, section):
        if section.lines:
            body = ' '.join(section.lines)
            if len(body.split()) <= self.value:
                return Result('body_max_length', True, self.wtype,
                               f'Body size is within the max length ({self.value} words).')
        return Result('body_max_length', False, self.wtype,
                       f'Body has more than {self.value} words.')

    def body_is_not_empty(self, section):
        body = ''.join(section.lines)
        if len(body) > self.value:
            return Result('body_is_not_empty', True, self.wtype,
                           'Body is not empty.')
        return Result('body_is_not_empty', False, self.wtype,
                       'Body is empty.')

    def body_has_three_paragraphs(self, section):
        # The parser strips blank lines, so paragraph boundaries are not
        # available here; we approximate "what/why/how" by requiring at least
        # three content lines rather than exactly three.
        if section.lines and len(section.lines) >= 3:
            return Result('body_has_three_paragraphs', True, self.wtype,
                           'Body follows the what, why and how structure (at least three paragraphs).')
        return Result('body_has_three_paragraphs', False, self.wtype,
                       'Body doesn\'t follow the what, why and how structure (at least three paragraphs).')

    def entity_label(self, section):
        """
        Generic metadata check: the tagged section must carry an entity with
        the required NER label. Parametrized via rules.yml
        (check/requires_label/subject), replacing the per-tag metadata methods.
        """
        if self.tag == section.tag:
            entities = section.entities or []
            if any(entity.label == self.requires_label for entity in entities):
                return Result(self.name, True, self.wtype,
                               f'Metadata mentions {self.subject}.')
            return Result(self.name, False, self.wtype,
                           f'Metadata section has {self.tag} tag but no {self.subject} was found.')
        return Result(self.name, False, self.wtype,
                       f'Metadata section is missing {self.subject} tag/mention.')

    def metadata_has_cvss(self, section):
        # security_ner has no CVSS label, so validate the value's shape instead
        # of accepting any text: a CVSS is a numeric score or a vector string
        # (which always carries digits, e.g. "7.5" or "CVSS:3.1/AV:N/...").
        if 'cvss' == section.tag and section.lines:
            value = ''.join(section.lines).split(':', 1)[-1]
            if re.search(r'\d', value):
                return Result('metadata_has_cvss', True, self.wtype,
                               f'Metadata mentions cvss score.')
            return Result('metadata_has_cvss', False, self.wtype,
                           f'Metadata has cvss tag but the value is not a valid score or vector.')
        return Result('metadata_has_cvss', False, self.wtype,
                       f'Metadata section is missing cvss tag/mention.')

    def contact_email(self, section):
        """
        Generic contact check: the tagged contact line must carry an EMAIL
        entity. Shared by reported-by/signed-off-by/co-authored-by via
        rules.yml (check: contact_email); `value` holds the human tag name.
        """
        if self.tag == section.tag and section.lines:
            entities = section.entities or []
            if any(entity.label == CommonLabel.EMAIL for entity in entities):
                return Result(self.name, True, self.wtype,
                               f'Contacts section includes {self.value} info.')
            return Result(self.name, False, self.wtype,
                           f'Contacts section includes tag for {self.value} but email is missing.')
        return Result(self.name, False, self.wtype,
                       f'Contacts section is missing {self.value} info.')

    def bugtracker_has_reference(self, section):
        if 'reference' == section.tag and section.lines:
            line = ''.join(section.lines)
            if 'bug-tracker' in line:
                entities = section.entities
                url = [entity.text
                       for entity in entities if entity.label == CommonLabel.URL]
                if url:
                    return Result('bugtracker_has_reference', True, self.wtype,
                                   f'Bug tracker section includes url.')
                return Result('bugtracker_has_reference', False, self.wtype,
                               f'Bug tracker section mentions bug tracker but is missing url to it.')

            if 'resolves' in line or 'see also' in line or 'fixes' in line:
                entities = section.entities
                refs = [entity.text
                        for entity in entities
                        if entity.label in (CommonLabel.ISSUE, CommonLabel.SHA)]
                if refs:
                    return Result('bugtracker_has_reference', True, self.wtype,
                                   f'Bug tracker section includes references to issues or commits.')

        return Result('bugtracker_has_reference', False, self.wtype,
                       f'Bug tracker section is missing bug-tracker info.')
