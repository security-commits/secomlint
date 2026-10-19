"""CLI tests for secomlint.__main__ using click's CliRunner.

The default/CSV lint paths run the real NER (cached across the suite); the
generation path is exercised only up to the missing-key error, so no network
or git repository is required.
"""

import json

import pandas as pd
import pytest
from click.testing import CliRunner

from secomlint.__main__ import main


# A message with no errors (all type-1 rules satisfied); it still has warnings
# for the optional metadata/contacts it omits.
MSG = (
    "vuln-fix: prevent path traversal (cve-2024-1234)\n"
    "\n"
    "an attacker could read arbitrary files via ../ sequences.\n"
    "this exposes sensitive configuration to unauthenticated users.\n"
    "the fix validates the resolved path against an allowed root.\n"
    "\n"
    "weakness: cwe-22\n"
    "severity: high\n"
    "reported-by: jane (jane@example.com)\n"
    "signed-off-by: john (john@example.com)\n"
)

# A weak message that triggers errors (no vuln-fix type, no weakness/severity, ...).
WEAK = "fix: corrige um bug\n\nmudei uma coisa.\n"


@pytest.fixture
def runner():
    return CliRunner()


def _write(tmp_path, text):
    path = tmp_path / "msg.txt"
    path.write_text(text)
    return str(path)


def test_lint_file_reports_score(runner, tmp_path):
    result = runner.invoke(main, ["--score", "--file-path", _write(tmp_path, MSG)])
    assert result.exit_code == 0
    assert "compliance" in result.output.lower()
    assert "%" in result.output
    assert "error(s)" in result.output


def test_lint_reads_from_stdin(runner):
    result = runner.invoke(main, ["--score"], input=MSG)
    assert result.exit_code == 0
    assert "%" in result.output


def test_quiet_hides_compliant_lines(runner, tmp_path):
    full = runner.invoke(main, ["--file-path", _write(tmp_path, MSG)])
    quiet = runner.invoke(main, ["--quiet", "--file-path", _write(tmp_path, MSG)])
    assert quiet.exit_code == 0
    # Compliant results (✅) are shown without --quiet and hidden with it.
    assert "✅" in full.output
    assert "✅" not in quiet.output
    # The summary line is still printed.
    assert "error(s)" in quiet.output


def test_csv_requires_out(runner, tmp_path):
    csv = tmp_path / "in.csv"
    pd.DataFrame({"commit_message": [MSG]}).to_csv(csv, index=False)
    result = runner.invoke(main, ["--compliance", "--csv", str(csv)])
    assert result.exit_code != 0
    assert "out is required" in result.output.lower()


def test_csv_batch_adds_score_and_entities_columns(runner, tmp_path):
    csv_in = tmp_path / "in.csv"
    csv_out = tmp_path / "out.csv"
    pd.DataFrame({"commit_message": [MSG]}).to_csv(csv_in, index=False)

    result = runner.invoke(
        main, ["--compliance", "--csv", str(csv_in), "--out", str(csv_out)]
    )
    assert result.exit_code == 0, result.output

    out = pd.read_csv(csv_out)
    assert "commit_message_score" in out.columns
    assert "commit_message_entities" in out.columns
    # Score is a fraction in [0, 1].
    assert 0.0 <= float(out.loc[0, "commit_message_score"]) <= 1.0


def test_generation_without_api_key_errors(runner, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = runner.invoke(main, ["--generation", "--provider", "openai"])
    assert result.exit_code != 0
    assert "api key" in result.output.lower()


def test_clean_message_exits_zero(runner, tmp_path):
    result = runner.invoke(main, ["--file-path", _write(tmp_path, MSG)])
    assert result.exit_code == 0


def test_message_with_errors_exits_nonzero(runner, tmp_path):
    result = runner.invoke(main, ["--file-path", _write(tmp_path, WEAK)])
    assert result.exit_code == 1


def test_json_output_is_valid_and_structured(runner, tmp_path):
    result = runner.invoke(main, ["--json", "--file-path", _write(tmp_path, MSG)])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert set(data) >= {"score", "errors", "warnings", "compliant", "total_rules", "results"}
    assert data["total_rules"] == 17
    assert len(data["results"]) == 17
    first = data["results"][0]
    assert set(first) >= {"rule", "status", "severity", "message", "doc"}
    assert first["status"] in {"compliant", "warning", "error"}


def test_json_output_still_sets_exit_code(runner, tmp_path):
    result = runner.invoke(main, ["--json", "--file-path", _write(tmp_path, WEAK)])
    assert result.exit_code == 1
    data = json.loads(result.output)   # JSON is still emitted alongside the failure
    assert data["errors"] > 0
