from secomlint.config import Config
from secomlint.ruler import Ruler


def test_default_config_exposes_generation_settings():
    config = Config()
    assert config.generation.get("provider") == "openai"
    assert config.generation.get("model") == "gpt-4o-mini"


def test_generation_key_is_not_a_compliance_rule():
    config = Config()
    # The reserved key must be separated out so the Ruler never sees it.
    assert "generation" not in config.default_rules
    # And the Ruler must build cleanly from the default rules.
    rules = Ruler(config).rules
    assert all(rule.name != "generation" for rule in rules)


def _write_yaml(tmp_path, text):
    path = tmp_path / "rules.yml"
    path.write_text(text)
    return str(path)


def test_user_config_overrides_generation(tmp_path):
    path = _write_yaml(
        tmp_path,
        "generation:\n  provider: ollama\n  model: llama3.2\n",
    )
    config = Config(path=path)
    assert config.generation["provider"] == "ollama"
    assert config.generation["model"] == "llama3.2"


def test_user_config_partial_override_keeps_defaults(tmp_path):
    path = _write_yaml(tmp_path, "generation:\n  model: custom-model\n")
    config = Config(path=path)
    # model overridden, provider falls back to the packaged default
    assert config.generation["model"] == "custom-model"
    assert config.generation["provider"] == "openai"


def test_user_config_without_generation_keeps_defaults(tmp_path):
    path = _write_yaml(tmp_path, "header_max_length:\n  active: true\n  type: 0\n  value: 60\n")
    config = Config(path=path)
    assert config.generation["provider"] == "openai"
    # the rule override still applies
    assert config.default_rules["header_max_length"]["value"] == 60
