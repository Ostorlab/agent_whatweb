"""Behavioral tests for the Apache Solr plugin's dual-marker match."""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_solr_check.rb"


def testPlugin_whenSolrLandingOrLookalikes_matchesOnlyTheDualMarkerPage() -> None:
    """Both the Solr Admin title and the ng-app marker are required."""
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
