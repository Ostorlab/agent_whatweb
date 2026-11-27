"""Behavioral test for the Hex (hexpm) landing markers."""

import pathlib
import shutil
import subprocess

import pytest

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_hex_check.rb"


def testPlugin_whenHexpmLandingOrLookalikes_matchesOnlyTheProductLanding() -> None:
    """The landing title and Erlang-ecosystem description identify Hex."""
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
