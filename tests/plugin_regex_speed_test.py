"""Checks that the plugins' regexes stay fast, so WhatWeb do not hang on them."""

import pathlib
import subprocess

PLUGINS_DIRECTORY = pathlib.Path(__file__).parent.parent / "plugins"
CHECK_SCRIPT = pathlib.Path(__file__).parent / "plugin_regex_speed_check.rb"
REGEX_TIME_LIMIT_SECONDS = 1


def testPluginRegexes_whenRunOnLargeNonAsciiPage_finishUnderTimeLimit() -> None:
    """Every plugin regex must scan a 230 KB page with non-ASCII text very fast."""
    result = subprocess.run(
        [
            "ruby",
            str(CHECK_SCRIPT),
            str(PLUGINS_DIRECTORY),
            str(REGEX_TIME_LIMIT_SECONDS),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
