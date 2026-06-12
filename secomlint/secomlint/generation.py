import os
import subprocess

import click
from openai import OpenAI


DEFAULT_MODEL = "gpt-4o-mini"

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
    """Generate a SECOM-compliant commit message for the changes in HEAD."""

    def __init__(self, key=None, model=DEFAULT_MODEL) -> None:
        api_key = key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "No OpenAI API key provided. Pass --openai-key or set the "
                "OPENAI_API_KEY environment variable."
            )
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.code_changes = self._read_head_diff()
        self.prompt = TEMPLATE + self.code_changes
        self.message = None

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
        response = self.client.chat.completions.create(
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
