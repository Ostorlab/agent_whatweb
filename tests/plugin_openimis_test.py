"""Behavioral tests for the openIMIS plugin's landing marker."""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_openimis_check.rb"


def testPlugin_whenOpenIMISLandingOrLookalikes_matchesOnlyTheProductTitle() -> None:
    """The exact openIMIS title identifies the product; lookalikes do not."""
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
