"""Behavioral tests for the Gitea Mirror plugin's product markers."""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_gitea_mirror_check.rb"


def testPlugin_whenGiteaMirrorPagesOrLookalikes_matchesOnlyTheProductMarkers() -> None:
    """The title plus shell marker identify Gitea Mirror, not a lookalike."""
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
