from __future__ import annotations

import io
import json
import sys

from compliancekit import cli


def test_cli_masks_findings_without_exposing_raw_input(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["compliancekit", "--json"])
    monkeypatch.setattr(sys, "stdin", io.StringIO("Contact synthetic@example.test"))
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert json.loads(output)["summary"]["total_findings"] == 1
    assert "synthetic@example.test" not in output


def test_cli_rejects_oversized_stream_before_scanning(monkeypatch, capsys):
    class BoundedStream:
        def read(self, size):
            assert size == cli.MAX_INPUT_CHARS + 1
            return "x" * size

    monkeypatch.setattr(sys, "argv", ["compliancekit"])
    monkeypatch.setattr(sys, "stdin", BoundedStream())
    monkeypatch.setattr(cli, "detect_pii", lambda _text: (_ for _ in ()).throw(AssertionError()))
    assert cli.main() == 2
    assert "character limit" in capsys.readouterr().err


def test_cli_missing_file_returns_actionable_error_without_traceback(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "argv", ["compliancekit", "--file", str(tmp_path / "missing.txt")])
    assert cli.main() == 2
    output = capsys.readouterr()
    assert "readable UTF-8" in output.err
    assert "Traceback" not in output.err
    assert not output.out


def test_cli_rejects_invalid_utf8_without_echoing_input(monkeypatch, capsys, tmp_path):
    sample = tmp_path / "invalid.txt"
    sample.write_bytes(b"private-synthetic-data\xff")
    monkeypatch.setattr(sys, "argv", ["compliancekit", "--file", str(sample)])
    assert cli.main() == 2
    assert "private-synthetic-data" not in capsys.readouterr().err
