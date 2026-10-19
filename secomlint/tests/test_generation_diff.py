"""Tests for Generation._read_head_diff (git diff extraction).

subprocess.run is monkeypatched so no real git repository is touched.
"""

import secomlint.generation as gen_mod
from secomlint.generation import Generation


class _FakeProc:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout.encode("utf-8")
        self.stderr = b""


def _patch_git(monkeypatch, output: str):
    monkeypatch.setattr(gen_mod.subprocess, "run", lambda *a, **k: _FakeProc(output))


def test_read_head_diff_strips_commit_metadata(monkeypatch):
    raw = (
        "commit deadbeef\n"
        "Author: Someone <s@example.com>\n"
        "\n"
        "    vuln-fix: patch\n"
        "\n"
        "diff --git a/f.py b/f.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
    _patch_git(monkeypatch, raw)

    out = Generation._read_head_diff()

    assert out.startswith("diff --git")
    assert "Author:" not in out          # commit metadata dropped
    assert "+new" in out                 # hunk kept


def test_read_head_diff_keeps_all_file_diffs(monkeypatch):
    raw = (
        "commit deadbeef\n\n    msg\n\n"
        "diff --git a/one.py b/one.py\n@@ -1 +1 @@\n+a\n"
        "diff --git a/two.py b/two.py\n@@ -1 +1 @@\n+b\n"
    )
    _patch_git(monkeypatch, raw)

    out = Generation._read_head_diff()

    assert out.count("diff --git") == 2


def test_read_head_diff_without_diff_returns_empty(monkeypatch):
    _patch_git(monkeypatch, "commit deadbeef\nAuthor: x\n\n    message only\n")
    assert Generation._read_head_diff() == ""
