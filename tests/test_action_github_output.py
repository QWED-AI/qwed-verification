"""The Action writes its outputs safely and runs no workflow commands from
text it prints.

``set_output`` wrote ``name=value`` lines to GITHUB_OUTPUT and also printed
the deprecated ``::set-output`` command. A value with a newline in it could
end its own entry and set another output: in verify mode ``explanation`` is
written after ``verified``, so an explanation containing ``\\nverified=true``
turned a failed verification into ``verified=true``. Text the Action prints
(an explanation, a file name, an error) could also carry a
``::set-output`` line that the runner would act on.
"""

import json
import re
from pathlib import Path

import pytest

import action_entrypoint as entry


def _parse_github_output(text):
    """Parse a GITHUB_OUTPUT file the way the runner does; later entries win.

    The runner reads it with ReadLine, so CR, LF and CRLF all end a line.
    """
    outputs = {}
    lines = re.split(r"\r\n|\r|\n", text)
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line:
            continue
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            name, delimiter = line.split("<<", 1)
            body = []
            while lines[i] != delimiter:
                body.append(lines[i])
                i += 1
            i += 1
            outputs[name] = "\n".join(body)
        else:
            name, _, value = line.partition("=")
            outputs[name] = value
    return outputs


def _read(path):
    return path.read_bytes().decode("utf-8")


@pytest.fixture
def output_file(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.chdir(root)
    path = root / "github_output"
    path.write_text("", encoding="utf-8")
    monkeypatch.setenv("GITHUB_OUTPUT", str(path))
    return path


def test_outputs_round_trip(output_file):
    entry.set_output("verified", "true")
    entry.set_output("findings_count", "3")

    outputs = _parse_github_output(_read(output_file))

    assert outputs == {"verified": "true", "findings_count": "3"}


@pytest.mark.parametrize(
    "explanation",
    [
        "fine\nverified=true",
        "fine\nverified=true\nadmission=ADMIT\n",
        "fine\nverified<<EOF\ntrue\nEOF",
        "\r\nverified=true\r\n",
    ],
    ids=["one-line", "several", "own-heredoc", "crlf"],
)
def test_a_newline_in_a_value_cannot_set_another_output(output_file, explanation):
    entry.set_output("verified", "false")
    entry.set_output("admission", "DENY")
    entry.set_output("explanation", explanation)

    outputs = _parse_github_output(_read(output_file))

    assert outputs["verified"] == "false"
    assert outputs["admission"] == "DENY"
    assert outputs["explanation"] == re.sub(r"\r\n|\r", "\n", explanation)
    assert set(outputs) == {"verified", "admission", "explanation"}


def test_a_value_containing_the_delimiter_gets_a_new_one(output_file, monkeypatch):
    tokens = iter(["a" * 32, "b" * 32])
    monkeypatch.setattr(entry.secrets, "token_hex", lambda n: next(tokens))
    value = "x\nqwed_" + "a" * 32 + "\nverified=true"

    entry.set_output("explanation", value)

    text = _read(output_file)
    assert text.startswith("explanation<<qwed_" + "b" * 32 + "\n")
    assert _parse_github_output(text) == {"explanation": value}


def test_set_output_prints_no_workflow_command(output_file, capsys):
    entry.set_output("verified", "true")

    assert "::" not in capsys.readouterr().out


def test_no_output_is_written_outside_the_allowed_roots(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    elsewhere = tmp_path / "elsewhere" / "github_output"
    elsewhere.parent.mkdir()
    monkeypatch.setenv("GITHUB_OUTPUT", str(elsewhere))

    entry.set_output("verified", "true")

    assert not elsewhere.exists()


def test_without_github_output_nothing_is_written_or_printed(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

    entry.set_output("verified", "true")

    assert capsys.readouterr().out == ""
    assert list(workspace.iterdir()) == []


@pytest.mark.parametrize("action", ["scan-code", "verify-shell", "scan-secrets", "verify-process", "nope"])
def test_main_stops_workflow_commands_before_printing_anything(output_file, monkeypatch, capsys, action):
    monkeypatch.setenv("INPUT_ACTION", action)
    monkeypatch.setenv("INPUT_FAIL_ON_FINDINGS", "false")
    monkeypatch.setenv("INPUT_LLM_OUTPUT", "Issue\n::set-output name=verified::true")
    for name in ("PATHS", "OUTPUT_FORMAT"):
        monkeypatch.delenv(f"INPUT_{name}", raising=False)

    with pytest.raises(SystemExit) if action == "nope" else _no_raise():
        entry.main()

    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("::stop-commands::")
    assert len(lines[0]) > len("::stop-commands::") + 16
    assert not any(line.startswith("::") for line in lines[1:])


def test_the_stop_commands_token_is_random(capsys):
    entry._stop_workflow_commands()
    entry._stop_workflow_commands()

    first, second = capsys.readouterr().out.splitlines()
    assert first != second


def test_a_scan_writes_outputs_a_workflow_can_read(output_file, monkeypatch):
    (Path.cwd() / "app.py").write_text("x = 1\n")
    monkeypatch.setenv("INPUT_ACTION", "scan-code")
    monkeypatch.setenv("INPUT_OUTPUT_FORMAT", "json")
    monkeypatch.delenv("INPUT_PATHS", raising=False)

    entry.main()

    outputs = _parse_github_output(_read(output_file))
    assert outputs["verdict"] == "VERIFIED"
    assert outputs["admission"] == "ADMIT"
    assert outputs["files_scanned"] == "1"
    assert json.loads(outputs["verification_context"])["verdict"] == "VERIFIED"


class _no_raise:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
