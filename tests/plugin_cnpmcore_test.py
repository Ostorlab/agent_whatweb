"""Behavioral tests for the cnpmcore plugin's total-data document markers."""

import pathlib
import shutil
import subprocess

import pytest

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_cnpmcore_check.rb"


def testPlugin_whenCnpmcoreDocumentsOrLookalikes_matchesOnlyTheProductDocument() -> (
    None
):
    """The total-data document identifies cnpmcore and yields the release."""
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
