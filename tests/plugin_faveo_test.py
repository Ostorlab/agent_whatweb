"""Behavioral tests for the Faveo Helpdesk guest-portal footer markers."""

import pathlib
import shutil
import subprocess

import pytest

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_faveo_check.rb"


def testPlugin_whenFaveoLandingsOrLookalikes_matchesOnlyTheProductFooter() -> None:
    """The shipped powered-by footer identifies Faveo; lookalikes do not."""
    if shutil.which("ruby") is None:
        pytest.skip("ruby not available")
    result = subprocess.run(
        [
            "ruby",
            str(CHECK_SCRIPT),
            str(PLUGINS_DIRECTORY),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
