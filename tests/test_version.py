"""One version number, used everywhere (it used to say 1.0, 1.1 and 1.3)."""

import re
import sys

import pytest

import scanner_cli
from scanner import __version__


def test_version_follows_semantic_versioning():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_cli_reports_the_version(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["netscan", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        scanner_cli.main()

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"netscan {__version__}"


def test_dashboard_shows_the_version(client):
    assert f"Version {__version__}" in client.get("/").get_data(as_text=True)


def test_changelog_has_an_entry_for_this_version():
    with open("CHANGELOG.md", encoding="utf-8") as f:
        assert f"## [{__version__}]" in f.read()
