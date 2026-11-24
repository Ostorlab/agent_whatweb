"""Behavioral tests for the Pangolin plugin's product markers."""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_pangolin_check.rb"


def testPlugin_whenPangolinAuthPagesOrLookalikes_matchesOnlyTheProductMarkers() -> None:
    """The auth-page title suffix and pangolin.net link identify Pangolin."""
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
