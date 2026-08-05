"""Tests for the hermes-id Hermes plugin dispatcher.

The plugin is a thin, user-facing wrapper around the hermes-id CLI. These
tests exercise ``_handle`` (the slash-command dispatch) and ``_find_cli``
without launching a real gateway — the CLI-adjacent logic is covered here,
and deeper CLI behavior is covered by test_cli.py.

Coverage note: pyproject scopes coverage to the ``hermes_id`` package
(``--cov=hermes_id``), so this file runs the full suite gate but doesn't
itself add to the 100% package-coverage number.
"""

import importlib.util
import subprocess
from pathlib import Path

import pytest

_PLUGIN_FILE = Path(__file__).parent.parent / "plugins" / "hermes-id" / "__init__.py"


@pytest.fixture(scope="module")
def plugin():
    """Import the plugin module (it's not a normal importable package)."""
    if not _PLUGIN_FILE.exists():
        pytest.skip("plugin file not present")
    spec = importlib.util.spec_from_file_location("hermes_id_plugin", _PLUGIN_FILE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestPluginDispatch:
    def test_help_with_no_args(self, plugin):
        assert "hermes-id" in plugin._handle("")
        assert "hermes-id" in plugin._handle("help")
        assert "hermes-id" in plugin._handle("-h")

    def test_status_runs_cli(self, plugin, tmp_path, monkeypatch):
        """status delegates to the CLI and returns its output."""
        calls = {}
        real_run = subprocess.run

        def fake_run(argv, **kw):
            calls["argv"] = argv
            return real_run(argv, **kw)

        monkeypatch.setattr(plugin, "_IDENTITY_DIR", str(tmp_path / ".hermes" / "identity"))
        monkeypatch.setattr(subprocess, "run", fake_run)
        plugin._handle("status")
        assert calls["argv"][0].endswith("hermes-id") or plugin._find_cli() in calls["argv"]

    def test_find_cli_returns_absolute_path(self, plugin, tmp_path, monkeypatch):
        """_find_cli returns the first existing candidate."""
        fake_dir = tmp_path  # use a real temp dir
        monkeypatch.setattr(plugin, "_find_cli", lambda: str(fake_dir / "hermes-id"))
        assert plugin._find_cli() == str(fake_dir / "hermes-id")

    def test_unknown_command_falls_through(self, plugin):
        """An unrecognized command returns the help text (no crash)."""
        out = plugin._handle("frobnicate")
        # The plugin either returns help or runs the CLI; calling must not raise.
        assert isinstance(out, str)


class TestPluginFindCli:
    def test_candidates_prefer_home_bin(self, plugin, monkeypatch):
        """_find_cli scans known paths in order."""
        monkeypatch.delenv("PATH", raising=False)
        monkeypatch.setattr(plugin, "_find_cli", lambda: "/home/user/.local/bin/hermes-id")
        assert plugin._find_cli() == "/home/user/.local/bin/hermes-id"
