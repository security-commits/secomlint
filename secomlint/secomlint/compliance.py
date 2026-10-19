from secomlint.rule import Rule
from secomlint.config import Config
from secomlint.ruler import Ruler
import click


class Compliance:
    def __init__(self, config, ruler=None) -> None:
        # The Ruler is read-only during check(), so it can be built once and
        # shared across many Compliance instances (e.g. one per CSV row),
        # avoiding a rules.yml re-read + rule rebuild on every message.
        self.ruler = ruler if ruler is not None else Ruler(Config(path=config.rules_config_path))
        self.results = []
        self.score = 0
        self.warnings = 0
        self.errors = 0
        self.compliant = 0
        # Severity-aware view (filled in by calculate_score): required = the
        # error-type rules (SECOM must-haves), recommended = the warning-type.
        self.valid = True
        self.completeness = 1.0
        self.required_total = 0
        self.required_passed = 0
        self.recommended_total = 0
        self.recommended_passed = 0

    def check(self, message, section=None):
        sections = [section] if section else message.sections
        mid = 0
        for section in sections:
            section_rules = self.ruler.get_section_rules(
                section,
                tag=section.tag
            )
            for rule in section_rules:
                if rule.active:
                    # Data-driven rules name a generic handler via `check`;
                    # the rest still resolve to a method named after the rule.
                    func_rule = getattr(Rule, rule.check or rule.name)
                    result = func_rule(rule, section)
                    # ordering warnings
                    if not result.is_compliant and result.type == 1:
                        self.results = [result] + self.results
                        mid += 1
                        self.errors += 1
                    elif not result.is_compliant and result.type == 0:
                        self.results = self.results[0:mid] + \
                            [result] + self.results[mid::]
                        self.warnings += 1
                    elif result.is_compliant:
                        self.results = self.results + [result]
                        self.compliant += 1

    def calculate_score(self):
        no_rules = sum(1 for rule in self.ruler.rules if rule.active)
        rules_in_compliance = sum(
            [result.is_compliant for result in self.results])
        self.score = (rules_in_compliance / no_rules) if no_rules else 0.0

        # Severity-aware view: a message is "valid" when every required
        # (error-type) rule passes; "completeness" is the share of the
        # recommended (warning-type) rules it also satisfies.
        required = [r for r in self.results if r.type == 1]
        recommended = [r for r in self.results if r.type == 0]
        self.required_total = len(required)
        self.required_passed = sum(r.is_compliant for r in required)
        self.recommended_total = len(recommended)
        self.recommended_passed = sum(r.is_compliant for r in recommended)
        self.valid = self.required_passed == self.required_total
        self.completeness = (
            self.recommended_passed / self.recommended_total
            if self.recommended_total else 1.0
        )

    def report(self, quiet, score):
        def get_symbol(is_compliant, warning_type):
            if is_compliant:
                return "✅"
            return "❌" if warning_type == 1 else "🟡"

        for result in self.results:
            symbol = get_symbol(result.is_compliant, result.type)
            doc_link = click.style(result.link, fg="blue")
            if result.is_compliant and quiet:
                continue
            click.echo(f"{symbol}  {result.message} {doc_link}")

        color = 'green' if self.errors == 0 and self.warnings == 0 else 'yellow'
        summary = f"\nfound {self.errors} error(s), {self.warnings} warning(s);"

        if score:
            secom_link = f"[\u001b]8;;https://security-commits.org/secom\u001b\\SECOM\u001b]8;;\u001b\\]"
            click.echo(
                click.style(
                    (f"{summary} 🎯 Commit message is {self.score*100:.2f}% in compliance with {secom_link} convention."),
                    fg=color,
                    bold=True))
            valid_txt = "yes" if self.valid else "no"
            click.echo(
                click.style(
                    (f"required {self.required_passed}/{self.required_total} passed "
                     f"(valid SECOM: {valid_txt}); recommended "
                     f"{self.recommended_passed}/{self.recommended_total} "
                     f"({self.completeness*100:.0f}% complete)."),
                    fg=color))
        else:
            click.echo(click.style(summary, fg=color, bold=True))

    def to_dict(self):
        """Machine-readable view of the compliance run (for --json / CI)."""
        def status(result):
            if result.is_compliant:
                return "compliant"
            return "error" if result.type == 1 else "warning"

        return {
            "score": self.score,
            "valid": self.valid,
            "completeness": self.completeness,
            "required": {"passed": self.required_passed, "total": self.required_total},
            "recommended": {"passed": self.recommended_passed, "total": self.recommended_total},
            "errors": self.errors,
            "warnings": self.warnings,
            "compliant": self.compliant,
            "total_rules": len(self.ruler.rules),
            "results": [
                {
                    "rule": result.rule_name,
                    "status": status(result),
                    "severity": result.type,
                    "message": result.message,
                    "doc": result.doc,
                }
                for result in self.results
            ],
        }

    def get_results(self):
        return self.results
