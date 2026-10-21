"""Tests for the offline/online NER model selection.

``default_model_name`` is environment-driven: offline by default, online when
``SECURITY_NER_ENDPOINT`` is set. These tests do not load any model or touch
the network: they only check which name is chosen.
"""

import pytest

from secomlint.message import default_model_name


def test_offline_by_default(monkeypatch):
    monkeypatch.delenv("SECURITY_NER_ENDPOINT", raising=False)
    assert default_model_name() == "commits"


def test_online_when_endpoint_configured(monkeypatch):
    monkeypatch.setenv("SECURITY_NER_ENDPOINT", "https://api.example.test")
    assert default_model_name() == "commits-remote"


def test_empty_endpoint_stays_offline(monkeypatch):
    # An empty value is treated as "not configured", so we stay offline.
    monkeypatch.setenv("SECURITY_NER_ENDPOINT", "")
    assert default_model_name() == "commits"
