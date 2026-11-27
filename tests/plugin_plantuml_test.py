"""Behavioral tests for the PlantUML Server plugin's product markers.

The Ruby check script loads the plugin with a minimal DSL stand-in, so the
editor title, release footer and generated-PNG regexes are exercised without
starting the WhatWeb runtime.
"""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_plantuml_check.rb"


def testPlugin_whenPlantUMLLandingsOrLookalikes_matchesOnlyTheProduct() -> None:
    """The editor/footer/PNG markers identify PlantUML; lookalikes do not."""
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
