import click

from secomlint.section import Body


# Entity labels produced by the Extractor (patterns.jsonl). SECWORD appears in
# both casings in the pattern set, so it is matched case-insensitively.
SECWORD = "SECWORD"
DETECTION = "DETECTION"
CWEID = "CWEID"
SEVERITY = "SEVERITY"

# Triage coverage -> informativeness level. The cutoffs are an ordinal over the
# number of SECOM triage systems (Detection/Assessment/Prioritization) the
# message can support.
LEVELS = {0: "none", 1: "low", 2: "medium", 3: "high"}


class Informativeness:
    """Measure how informative a security commit message is.

    Two axes:
    * body informativeness — security-related words (SECWORD) in the body;
    * triage support — whether the message carries enough information for the
      SECOM triage systems: Detection (D), Assessment (A) and Prioritization (P).
    """

    def __init__(self, message) -> None:
        # Group entities by the section type they came from.
        self.entities = {}
        for section in message.sections:
            if not section.entities:
                continue
            self.entities.setdefault(type(section).__name__, []).extend(section.entities)

        bodies = [s for s in message.sections if isinstance(s, Body)]
        self.body = bodies[0] if bodies else None

        self.body_secwords = set()
        self.detection = False
        self.assessment = False
        self.prioritization = False
        self.level = None

    def _all_entities(self):
        return [entity for entities in self.entities.values() for entity in entities]

    @staticmethod
    def _has_label(entities, label):
        return any(entity[1].upper() == label for entity in entities)

    def check_body(self):
        """Collect the security-related words found in the body."""
        body_entities = self.entities.get("Body", [])
        self.body_secwords = {
            entity[0] for entity in body_entities if entity[1].upper() == SECWORD
        }
        return self.body_secwords

    def triage_systems(self):
        """Determine which SECOM triage systems the message supports."""
        all_entities = self._all_entities()
        self.detection = self._has_label(all_entities, DETECTION)
        self.assessment = self._has_label(all_entities, CWEID)
        self.prioritization = self._has_label(all_entities, SEVERITY)
        return self.detection, self.assessment, self.prioritization

    def calculate_level(self):
        """Compute body words, triage coverage and the overall level."""
        self.check_body()
        self.triage_systems()
        triage_score = sum([self.detection, self.assessment, self.prioritization])
        self.level = LEVELS[triage_score]
        return self.level

    def evaluate(self):
        """Run the full analysis and return a structured result."""
        self.calculate_level()
        return {
            "body_secwords": sorted(self.body_secwords),
            "detection": self.detection,
            "assessment": self.assessment,
            "prioritization": self.prioritization,
            "level": self.level,
        }

    def report(self):
        """Print a human-readable informativeness report."""
        self.evaluate()

        if self.body_secwords:
            click.echo(
                "👍 Good to go! Extractor found the following security-related "
                "words in the message's body:"
            )
            for word in sorted(self.body_secwords):
                click.echo(click.style(f"   - {word}", fg="green"))
        else:
            click.echo(
                "🧐 The message's body is not informative enough. Try improving "
                "it by adding more security-related words!"
            )

        click.echo(f"Detection (D): {self.detection}")
        click.echo(f"Assessment (A): {self.assessment}")
        click.echo(f"Prioritization (P): {self.prioritization}")
        click.echo(
            click.style(f"🎯 Informativeness level: {self.level}", bold=True)
        )
