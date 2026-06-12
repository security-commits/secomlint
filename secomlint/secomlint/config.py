import os
from pathlib import Path
from typing import Optional

from secomlint.utils import read_config


class Config:
    def __init__(self, path: Optional[str] = None) -> None:

        # Build paths in a cross-platform manner
        base_dir = Path(__file__).resolve().parent / "config"
        self.rules_config_path = base_dir / "rules.yml"

        # Read the default rules if the file exists; fallback to empty dict
        self.default_rules = read_config(str(self.rules_config_path)) or {}

        # Merge new rules if a path is provided
        if path is not None:
            new_rules = read_config(path) or {}
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
