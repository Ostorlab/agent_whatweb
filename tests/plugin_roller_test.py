"""Behavioral tests for the Apache Roller plugin's product markers.

The Ruby check script loads the plugin with a minimal DSL stand-in, so the
Roller UI asset, front-page/setup-page product marker and footer-version
regexes are exercised without starting the WhatWeb runtime.
"""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_roller_check.rb"


def testPlugin_whenRollerLandingOrLookalikes_matchesOnlyTheProductMarkers() -> None:
    """The Roller UI paths and product marker identify the product; lookalikes do not."""
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
