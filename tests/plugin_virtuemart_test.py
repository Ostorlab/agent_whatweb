"""Behavioral tests for the VirtueMart plugin's product-specific asset marker.

The Ruby check script loads the plugin with a minimal DSL stand-in, so the
asset-path regex is exercised without starting the WhatWeb runtime.
"""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_virtuemart_check.rb"


def testPlugin_whenVirtueMartLandingOrLookalikes_matchesOnlyTheProductAssets() -> None:
    """The VirtueMart asset path identifies the component; lookalikes do not."""
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
