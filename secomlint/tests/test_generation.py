from unittest.mock import MagicMock, patch

import pytest

from secomlint.generation import Generation, OLLAMA_BASE_URL, DEFAULT_MODELS


def _fake_chat_completion(text):
    resp = MagicMock()
    choice = MagicMock()
    choice.message.content = text
    resp.choices = [choice]
    return resp


def _fake_anthropic_message(text):
    resp = MagicMock()
    block = MagicMock()
    block.type = "text"
    block.text = text
    resp.content = [block]
    return resp


# --- OpenAI / shared behaviour -------------------------------------------------

@patch("secomlint.generation.subprocess.run")
@patch("secomlint.generation.OpenAI")
def test_run_returns_generated_message(mock_openai, mock_run):
    mock_run.return_value.stdout = (
        b"commit abc123\nAuthor: x\n\n    old msg\n\n"
        b"diff --git a/f b/f\n@@\n+code"
    )
    client = mock_openai.return_value
    client.chat.completions.create.return_value = _fake_chat_completion(
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

    mock_openai.assert_called_once_with(api_key="sk-from-env", base_url=None)


def test_unknown_provider_raises():
    with pytest.raises(ValueError):
        Generation(provider="bogus", key="x")


# --- Ollama (OpenAI-compatible, local) -----------------------------------------

@patch("secomlint.generation.subprocess.run")
@patch("secomlint.generation.OpenAI")
def test_ollama_uses_local_base_url_without_key(mock_openai, mock_run):
    mock_run.return_value.stdout = b""

    gen = Generation(provider="ollama")  # no key required

    mock_openai.assert_called_once_with(base_url=OLLAMA_BASE_URL, api_key="ollama")
    assert gen.model == DEFAULT_MODELS["ollama"]


@patch("secomlint.generation.subprocess.run")
@patch("secomlint.generation.OpenAI")
def test_ollama_custom_base_url(mock_openai, mock_run):
    mock_run.return_value.stdout = b""

    Generation(provider="ollama", base_url="http://gpu-box:11434/v1")

    mock_openai.assert_called_once_with(base_url="http://gpu-box:11434/v1", api_key="ollama")


# --- Anthropic -----------------------------------------------------------------

@patch("secomlint.generation.subprocess.run")
@patch("anthropic.Anthropic")
def test_anthropic_run_parses_text_blocks(mock_anthropic, mock_run):
    mock_run.return_value.stdout = b"diff --git a/f b/f\n+x"
    client = mock_anthropic.return_value
    client.messages.create.return_value = _fake_anthropic_message(
        "vuln-fix: patch it (CVE-2)"
    )

    gen = Generation(provider="anthropic", key="sk-ant-test")
    msg = gen.run()

    assert msg == "vuln-fix: patch it (CVE-2)"
    assert gen.model == DEFAULT_MODELS["anthropic"]
    # Anthropic takes the system prompt as a top-level arg, not a message.
    _, kwargs = client.messages.create.call_args
    assert "system" in kwargs
    assert kwargs["messages"][0]["role"] == "user"


@patch("secomlint.generation.subprocess.run")
def test_anthropic_missing_key_raises(mock_run, monkeypatch):
    mock_run.return_value.stdout = b""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with patch("anthropic.Anthropic"):
        with pytest.raises(ValueError):
            Generation(provider="anthropic", key=None)
