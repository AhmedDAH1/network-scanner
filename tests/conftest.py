"""Shared test fixtures. pytest loads this file automatically."""

import pytest

import web_app


@pytest.fixture
def client():
    """A test client for the dashboard: sends requests without a real server."""
    web_app.app.config["TESTING"] = True
    return web_app.app.test_client()


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """Point the dashboard's data files at a fresh temporary folder."""
    monkeypatch.setattr(web_app, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(web_app, "HISTORY_FILE", str(tmp_path / "scan_history.json"))
    monkeypatch.setattr(web_app, "RESULTS_FILE", str(tmp_path / "scan_results.json"))
    return tmp_path


@pytest.fixture
def no_scanner(monkeypatch):
    """Fail the test if anything tries to start the real scanner process."""
    def refuse(*args, **kwargs):
        raise AssertionError(f"the scanner must not start here: {args!r}")
    monkeypatch.setattr(web_app.subprocess, "Popen", refuse)
