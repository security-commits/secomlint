import re

from security_ner import CommonLabel
from security_ner.models.commits.labels import DETECTION


class Result:
    def __init__(self, rule_name, result, wtype, wmessage) -> None:
        self.rule_name = rule_name
        self.is_compliant = result
        self.type = wtype
        self.message = wmessage
        self.link = f"[\u001b]8;;https://security-commits.org/secomlint/#/secomlint-rules?id={self.rule_name.replace('_', '-')}\u001b\\{self.rule_name}\u001b]8;;\u001b\\]"


class Rule:
    def __init__(self, name, active, wtype, value, section, tag=None) -> None:
        self.name = name
        self.active = active
        self.wtype = wtype
        self.value = value
        self.section = section
        self.tag = tag

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
        if re.search(rf"^{self.value}.*", section_text):
            return Result('header_starts_with_type', True, self.wtype,
                           f'Header starts with {self.value} type')
        return Result('header_starts_with_type', False, self.wtype,
                       f'Header is missing the {self.value} type at the start.')

    def header_ends_with_vuln_id(self, section):
        def vuln_id_at_the_end(value, text):
            return re.search(rf".*{value}(\))?$", text)
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
            body = ''.join(section.lines)
            if len(body) <= self.value:
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
        if len(section.lines) == 3:
            return Result('body_has_three_paragraphs', True, self.wtype,
                           'Body follows the what, why and how structure (three paragraphs).')
        return Result('body_has_three_paragraphs', False, self.wtype,
                       'Body doesn\'t follow the what, why and how structure (three paragraphs).')

    def metadata_has_weakness(self, section):
        if 'weakness' == section.tag:
            entities = section.entities
            if entities:
                weakness = [entity.text
                            for entity in entities if entity.label == CommonLabel.CWEID]
                if weakness:
                    return Result('metadata_has_weakness', True, self.wtype,
                                   'Metadata mentions a weakness (CWE) id.')
                return Result('metadata_has_weakness', False, self.wtype,
                               'Metadata has tag weakness but a weakness (CWE) id was not mentioned.')
        return Result('metadata_has_weakness', False, self.wtype,
                       'Metadata section is missing weakness tag/mention.')

    def metadata_has_severity(self, section):
        if 'severity' == section.tag:
            entities = section.entities
            if entities:
                severity = [entity.text for entity in entities
                            if entity.label == CommonLabel.SEVERITY]
                if severity:
                    return Result('metadata_has_severity', True, self.wtype,
                                   f'Metadata mentions severity.')
                return Result('metadata_has_severity', False, self.wtype,
                               f'Metadata section has severity tag but is missing vulnerability severity /mention.')
        return Result('metadata_has_severity', False, self.wtype,
                       f'Metadata section is missing vulnerability severity tag/mention.')

    def metadata_has_detection(self, section):
        if 'detection' == section.tag:
            entities = section.entities
            if entities:
                detection = [entity.text for entity in entities
                             if entity.label == DETECTION]
                if detection:
                    return Result('metadata_has_detection', True, self.wtype,
                                   f'Metadata mentions detection method.')
                return Result('metadata_has_detection', False, self.wtype,
                        f'Metadata section has detection tag but is missing detection method mention.')
        return Result('metadata_has_detection', False, self.wtype,
                       f'Metadata section is missing detection method tag/mention.')

    def metadata_has_report(self, section):
        if 'report' == section.tag:
            entities = section.entities
            if entities:
                url = [entity.text
                       for entity in entities if entity.label == CommonLabel.URL]
                if url:
                    return Result('metadata_has_report', True, self.wtype,
                                   f'Metadata mentions report.')
            return Result('metadata_has_report', False, self.wtype,
                           f'Metadata has report tag but does not have link to it.')
        return Result('metadata_has_report', False, self.wtype,
                       f'Metadata section is missing report tag/mention.')

    def metadata_has_cvss(self, section):
        if 'cvss' == section.tag and section.lines:
            return Result('metadata_has_cvss', True, self.wtype,
                           f'Metadata mentions cvss score.')
        return Result('metadata_has_cvss', False, self.wtype,
                       f'Metadata section is missing cvss tag/mention.')

    def metadata_has_introduced_in(self, section):
        if 'introduced_in' == section.tag:
            entities = section.entities
            if entities:
                sha = [entity.text
                       for entity in entities if entity.label == CommonLabel.SHA]
                if sha:
                    return Result('metadata_has_introduced_in', True, self.wtype,
                                   f'Metadata mentions sha where vulnerability was introduced in.')
            return Result('metadata_has_introduced_in', False, self.wtype,
                           f'Metadata mentions introduced in tag but no sha was found.')
        return Result('metadata_has_introduced_in', False, self.wtype,
                       f'Metadata section is missing introduced in tag/mention.')

    def contact_has_reported_by(self, section):
        if 'reported_by' == section.tag and section.lines:
            entities = section.entities
            email = [entity.text
                     for entity in entities if entity.label == CommonLabel.EMAIL]
            if email:
                return Result('contacts_has_reported_by', True, self.wtype,
                               f'Contacts section includes {self.value} info.')
            return Result('contacts_has_reported_by', False, 0,
                           f'Contacts section includes tag for {self.value} but email is missing.')
        return Result('contacts_has_reported_by', False, self.wtype,
                       f'Contacts section is missing {self.value} info.')

    def contact_has_signed_off_by(self, section):
        if 'signed_off_by' == section.tag and section.lines:
            entities = section.entities
            email = [entity.text
                     for entity in entities if entity.label == CommonLabel.EMAIL]
            if email:
                return Result('contact_has_signed_off_by', True, self.wtype,
                               f'Contacts section includes {self.value} info.')
            return Result('contact_has_signed_off_by', False, 0,
                           f'Contacts section includes tag or mention for {self.value} but email is missing.')
        return Result('contact_has_signed_off_by', False, self.wtype,
                       f'Contacts section is missing {self.value} info.')

    def contact_has_co_authored_by(self, section):
        if 'co_authored_by' == section.tag and section.lines:
            entities = section.entities
            email = [entity.text
                     for entity in entities if entity.label == CommonLabel.EMAIL]
            if email:
                return Result('contacts_has_co_authored_by', True, self.wtype,
                               f'Contacts section includes {self.value} info.')
            return Result('contacts_has_co_authored_by', True, 0,
                           f'Contacts section includes tag or mention for {self.value} but email is missing.')
        return Result('contacts_has_co_authored_by', False, self.wtype,
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

            if 'resolves' in line or 'see also' in line:
                entities = section.entities
                issue = [entity.text
                         for entity in entities if entity.label == CommonLabel.ISSUE]
                if issue:
                    return Result('bugtracker_has_reference', True, self.wtype,
                                   f'Bug tracker section includes references to issues.')

        return Result('bugtracker_has_reference', False, self.wtype,
                       f'Bug tracker section is missing bug-tracker info.')
