"""Behavioral tests for the Idno plugin's product markers.

The Ruby check script loads the plugin with a minimal DSL stand-in, so the
header and generator-meta regexes are exercised without starting the WhatWeb
runtime.
"""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_idno_check.rb"


def testPlugin_whenIdnoLandingOrLookalikes_matchesOnlyTheProductMarkers() -> None:
    """The powered-by header and generator meta identify Idno; a lookalike does not."""
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
