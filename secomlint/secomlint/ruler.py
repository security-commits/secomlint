from secomlint.rule import Rule

from secomlint.section import Header, Body, Metadata, Contact, Bugtracker

class Ruler:
    def __init__(self, config) -> None:
        self.rules = []
        for rule in config.default_rules:
            section_name = rule.split('_')[0]
            if section_name.capitalize() not in globals():
                raise ValueError(
                    f"rules.yml: rule '{rule}' has no known section "
                    f"(prefix '{section_name}')."
                )
            section = globals()[section_name.capitalize()]
            default_rule = config.default_rules[rule]
            # The rule resolves to a generic handler (`check`) or a method named
            # after the rule; fail fast with a clear error if it is missing.
            handler = default_rule.get('check') or rule
            if not hasattr(Rule, handler):
                raise ValueError(
                    f"rules.yml: rule '{rule}' references unknown handler "
                    f"'{handler}'."
                )
            self.rules.append(Rule(rule,
                                   default_rule['active'],
                                   default_rule['type'],
                                   default_rule['value']
                                   if 'value' in default_rule.keys() else 'entity',
                                   section(),
                                   tag='_'.join(rule.split('_')[2::])
                                   if section_name in ('metadata', 'contact', 'bugtracker')
                                   else None,
                                   check=default_rule.get('check'),
                                   requires_label=default_rule.get('requires_label'),
                                   subject=default_rule.get('subject'),
                                   ))

    def get_section_rules(self, section, tag=None):
        return [rule for rule in self.rules
                if type(rule.section) == type(section)
                and rule.tag == tag]
