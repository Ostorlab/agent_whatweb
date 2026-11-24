"""Behavioral tests for the Joomla CMS plugin's product markers."""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_joomla_cms_check.rb"


def testPlugin_whenJoomlaPagesOrLookalikes_matchesOnlyTheProductMarkers() -> None:
    """The generator meta, login page and installer page identify Joomla."""
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
