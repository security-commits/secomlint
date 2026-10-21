from pathlib import Path
from typing import Optional

from secomlint.utils import read_config


class Config:
    # Reserved top-level YAML keys that are not compliance rules.
    GENERATION_KEY = "generation"

    def __init__(self, path: Optional[str] = None) -> None:

        # Build paths in a cross-platform manner
        base_dir = Path(__file__).resolve().parent / "config"
        self.rules_config_path = base_dir / "rules.yml"

        # Read the default rules if the file exists; fallback to empty dict
        raw = read_config(str(self.rules_config_path)) or {}
        # Keep generation settings (provider/model/base_url) out of the rules
        # dict the Ruler consumes — it treats every key as a section rule.
        self.generation = dict(raw.pop(self.GENERATION_KEY, {}) or {})
        self.default_rules = raw

        # Merge a user-provided config if a path is given
        if path is not None:
            new_rules = read_config(path) or {}
            self.generation.update(new_rules.pop(self.GENERATION_KEY, {}) or {})
            self._merge_rules(new_rules)

    def _merge_rules(self, new_rules: dict) -> None:
        """
        Recursively merges new_rules into default_rules.
        """
        for rule, new_value in new_rules.items():
            if rule not in self.default_rules:
                self.default_rules[rule] = new_value
            else:
                old_value = self.default_rules[rule]
                if isinstance(old_value, dict) and isinstance(new_value, dict):
                    self._merge_rules_into(old_value, new_value)
                else:
                    self.default_rules[rule] = new_value

    def _merge_rules_into(self, base_dict: dict, new_dict: dict) -> None:
        """
        Helper function to recursively merge new_dict into base_dict.
        """
        for key, value in new_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._merge_rules_into(base_dict[key], value)
            else:
                base_dict[key] = value
