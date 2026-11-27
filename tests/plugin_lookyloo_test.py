"""Behavioral tests for the Lookyloo plugin's product-specific footer.

The Ruby check script loads the plugin with a minimal DSL stand-in, so the
combined brand/version footer regex is exercised without starting the WhatWeb
runtime.
"""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_lookyloo_check.rb"


def testPlugin_whenLookylooLandingOrLookalikes_matchesOnlyTheProductFooter() -> None:
    """The versioned footer identifies Lookyloo; lookalikes do not."""
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
