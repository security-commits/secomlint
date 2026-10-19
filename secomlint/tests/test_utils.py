"""Tests for secomlint.utils: read_config and extend_tags."""

import pytest

from secomlint.utils import read_config, extend_tags


def test_extend_tags_adds_space_variant_for_hyphenated():
    assert extend_tags(["bug-tracker", "resolves"]) == [
        "bug-tracker", "resolves", "bug tracker",
    ]


def test_extend_tags_leaves_unhyphenated_tags_unchanged():
    assert extend_tags(["resolves", "fixes"]) == ["resolves", "fixes"]


def test_extend_tags_does_not_mutate_input():
    tags = ["co-authored-by"]
    extend_tags(tags)
    assert tags == ["co-authored-by"]


def test_read_config_parses_yaml(tmp_path):
    path = tmp_path / "c.yml"
    path.write_text("a: 1\nb:\n  - x\n  - y\n")
    assert read_config(str(path)) == {"a": 1, "b": ["x", "y"]}


def test_read_config_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_config(str(tmp_path / "does_not_exist.yml"))
