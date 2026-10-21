import os
import subprocess

import click
from openai import OpenAI


# Default model per provider. Override with --model.
DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "ollama": "llama3.2",
    "anthropic": "claude-haiku-4-5-20251001",
}

# Ollama exposes an OpenAI-compatible API on this endpoint by default.
OLLAMA_BASE_URL = "http://localhost:11434/v1"

ENV_KEYS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

SYSTEM_PROMPT = (
    "You are an assistant that writes security commit messages following the "
    "SECOM convention (https://security-commits.org/secom/). Return only the "
    "commit message, with no surrounding explanation or code fences."
)

TEMPLATE = """Generate a commit message with the following structure

vuln-fix: <header/subject> (<Vuln-ID>)

<body>
# (what) describe the vulnerability/problem
# (why) describe its impact
# (how) describe the patch/fix

Weakness: <Weakness Name or CWE-ID>
Severity: <Low, Medium, High and Critical>
CVSS: <Numerical representation (0-10) of severity>
Detection: <Detection Method>
Report: <Report Link>
Introduced in: <Commit Hash>

Reported-by: <Name> (<Contact>)
Reviewed-by: <Name> (<Contact>)
Co-authored-by: <Name> (<Contact>)
Signed-off-by: <Name> (<Contact>)

Bug-tracker: <Bug-tracker Link>
OR
Resolves: <Issue/PR No.>
See also: <Issue/PR No.>

for the code changes below:

"""


class Generation:
    """Generate a SECOM-compliant commit message for the changes in HEAD.

    Supports OpenAI, a local/remote Ollama server (OpenAI-compatible API),
    and Anthropic, selected via ``provider``.
    """

    def __init__(self, provider="openai", key=None, model=None, base_url=None) -> None:
        if provider not in DEFAULT_MODELS:
            raise ValueError(
                f"Unknown provider '{provider}'. Choose from: "
                f"{', '.join(sorted(DEFAULT_MODELS))}."
            )
        self.provider = provider
        self.model = model or DEFAULT_MODELS[provider]
        self._client = self._build_client(provider, key, base_url)
        self.code_changes = self._read_head_diff()
        self.prompt = TEMPLATE + self.code_changes
        self.message = None

    def _build_client(self, provider, key, base_url):
        if provider == "anthropic":
            try:
                from anthropic import Anthropic
            except ImportError:
                raise ValueError(
                    "The 'anthropic' package is required for --provider anthropic. "
                    "Install it with: pip install secomlint[anthropic]"
                )
            api_key = key or os.environ.get(ENV_KEYS["anthropic"])
            if not api_key:
                raise ValueError(self._missing_key_message("anthropic"))
            return Anthropic(api_key=api_key)

        if provider == "ollama":
            # Local server: no real key needed, but the client requires one.
            return OpenAI(base_url=base_url or OLLAMA_BASE_URL, api_key=key or "ollama")

        # provider == "openai"
        api_key = key or os.environ.get(ENV_KEYS["openai"])
        if not api_key:
            raise ValueError(self._missing_key_message("openai"))
        return OpenAI(api_key=api_key, base_url=base_url)

    @staticmethod
    def _missing_key_message(provider) -> str:
        env = ENV_KEYS[provider]
        return (
            f"No {provider} API key provided. Pass --api-key or set the "
            f"{env} environment variable."
        )

    @staticmethod
    def _read_head_diff() -> str:
        """Return the diff hunks of HEAD, dropping the leading commit metadata."""
        result = subprocess.run(
            ["git", "show", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        output = result.stdout.decode("utf-8", errors="replace")
        parts = output.split("diff --git")
        if len(parts) <= 1:
            return ""
        return "diff --git" + "diff --git".join(parts[1:])

    def run(self) -> str:
        """Call the model and store the generated commit message."""
        if self.provider == "anthropic":
            response = self._client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": self.prompt}],
            )
            self.message = "".join(
                block.text
                for block in response.content
                if getattr(block, "type", None) == "text"
            ).strip()
        else:
            # openai and ollama share the OpenAI-compatible Chat Completions API.
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": self.prompt},
                ],
                temperature=0.7,
                max_tokens=500,
            )
            self.message = (response.choices[0].message.content or "").strip()
        return self.message

    def print(self) -> None:
        click.echo(click.style(self.message, fg="yellow"))

    def usage(self) -> str:
        """Show the message and ask the user how to use it. Returns Y/N/C."""
        self.print()
        click.echo(
            "\nWould you like to use this commit message?\n"
            "(Y - Yes (default); N - No; C - Yes, but I want to change it.)"
        )
        self.response = (input("Enter your answer (Y/N/C): ").strip().upper() or "Y")
        return self.response

    def save(self, edit: bool = False) -> None:
        """Amend HEAD with the generated message. If edit, open the editor first."""
        cmd = ["git", "commit", "--amend", "-m", self.message]
        if edit:
            cmd.insert(3, "-e")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        click.echo(result.stdout.decode("utf-8", errors="replace"))
