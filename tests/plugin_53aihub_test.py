"""Behavioral tests for the 53AIHub plugin's product markers.

The Ruby check script loads the plugin with a minimal DSL stand-in, so the
front-end title and analytics-id regexes are exercised without starting the
WhatWeb runtime.
"""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_53aihub_check.rb"


def testPlugin_when53AIHubLandingOrLookalikes_matchesOnlyTheProductMarkers() -> None:
    """The runtime title and analytics id identify 53AIHub; lookalikes do not."""
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
