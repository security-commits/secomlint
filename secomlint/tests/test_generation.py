from unittest.mock import MagicMock, patch

import pytest

from secomlint.generation import Generation


def _fake_completion(text):
    resp = MagicMock()
    choice = MagicMock()
    choice.message.content = text
    resp.choices = [choice]
    return resp


@patch("secomlint.generation.subprocess.run")
@patch("secomlint.generation.OpenAI")
def test_run_returns_generated_message(mock_openai, mock_run):
    mock_run.return_value.stdout = (
        b"commit abc123\nAuthor: x\n\n    old msg\n\n"
        b"diff --git a/f b/f\n@@\n+code"
    )
    client = mock_openai.return_value
    client.chat.completions.create.return_value = _fake_completion(
        "vuln-fix: do thing (CVE-1)"
    )

    gen = Generation(key="sk-test")
    msg = gen.run()

    assert msg == "vuln-fix: do thing (CVE-1)"
    # Commit metadata before the first "diff --git" is stripped from the prompt.
    assert gen.code_changes.startswith("diff --git")
    assert "old msg" not in gen.code_changes
    client.chat.completions.create.assert_called_once()


@patch("secomlint.generation.subprocess.run")
@patch("secomlint.generation.OpenAI")
def test_save_amends_with_message(mock_openai, mock_run):
    mock_run.return_value.stdout = b""
    gen = Generation(key="sk-test")
    gen.message = "vuln-fix: do thing (CVE-1)"

    gen.save()

    args = mock_run.call_args[0][0]
    assert args[:4] == ["git", "commit", "--amend", "-m"]
    assert args[4] == "vuln-fix: do thing (CVE-1)"


@patch("secomlint.generation.subprocess.run")
@patch("secomlint.generation.OpenAI")
def test_save_with_edit_opens_editor(mock_openai, mock_run):
    mock_run.return_value.stdout = b""
    gen = Generation(key="sk-test")
    gen.message = "vuln-fix: do thing (CVE-1)"

    gen.save(edit=True)

    args = mock_run.call_args[0][0]
    assert args == ["git", "commit", "--amend", "-e", "-m", "vuln-fix: do thing (CVE-1)"]


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with patch("secomlint.generation.OpenAI"):
        with pytest.raises(ValueError):
            Generation(key=None)


@patch("secomlint.generation.subprocess.run")
@patch("secomlint.generation.OpenAI")
def test_key_falls_back_to_env(mock_openai, mock_run, monkeypatch):
    mock_run.return_value.stdout = b""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")

    Generation(key=None)

    mock_openai.assert_called_once_with(api_key="sk-from-env")
