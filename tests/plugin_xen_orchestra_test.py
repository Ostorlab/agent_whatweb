"""Behavioral tests for the Xen Orchestra plugin's product markers.

The Ruby check script loads the plugin with a minimal DSL stand-in, so the
combined title/SPA-container regex is exercised without starting the WhatWeb
runtime.
"""

import pathlib
import shutil
import subprocess

import pytest

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_xen_orchestra_check.rb"


def testPlugin_whenXenOrchestraLandingOrLookalikes_matchesOnlyTheProductMarkers() -> (
    None
):
    """The title and SPA container identify Xen Orchestra; lookalikes do not."""
    if shutil.which("ruby") is None:
        pytest.skip("ruby not installed")
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
