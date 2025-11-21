"""Unittests for fingerprint MCP server."""

import pathlib
import subprocess

import pytest
from pytest_mock import plugin

from agent import definitions
from agent import whatweb_utils
from agent.mcp_server import tools

TESTS_DIR = pathlib.Path(__file__).parent


@pytest.fixture
def mock_whatweb_output() -> bytes:
    """Load mock WhatWeb output from test file."""
    return (TESTS_DIR / "output.json").read_bytes()


@pytest.fixture
def mock_ip_whatweb_output() -> bytes:
    """Load mock WhatWeb output for IP target from test file."""
    return (TESTS_DIR / "ip_output.json").read_bytes()


def testFingerprint_whenTargetIsValid_returnsFingerprints(
    mocker: plugin.MockerFixture,
    mock_whatweb_output: bytes,
) -> None:
    """Test fingerprint with valid target returns fingerprints correctly."""
    mocker.patch(
        "agent.whatweb_utils.run_whatweb_scan", return_value=mock_whatweb_output
    )

    result = tools.fingerprint(target="https://ostorlab.co:443")

    assert len(result) == 5
    fingerprint_names = [fp.name for fp in result]
    assert "Google-Analytics" in fingerprint_names
    assert "cloudflare" in fingerprint_names
    assert any(
        fp.name == "Google-Analytics" and fp.version == "Universal" for fp in result
    )


def testFingerprint_whenBlacklistedPlugins_filtersThemOut(
    mocker: plugin.MockerFixture,
    mock_whatweb_output: bytes,
) -> None:
    """Test fingerprint filters out blacklisted plugins."""
    mocker.patch(
        "agent.whatweb_utils.run_whatweb_scan", return_value=mock_whatweb_output
    )

    result = tools.fingerprint(target="https://ostorlab.co:443")

    blacklisted_names = [
        fp.name for fp in result if fp.name in definitions.BLACKLISTED_PLUGINS
    ]
    assert len(blacklisted_names) == 0


def testFingerprint_whenIPTarget_scansSuccessfully(
    mocker: plugin.MockerFixture,
    mock_ip_whatweb_output: bytes,
) -> None:
    """Test fingerprint with IP address target."""
    mocker.patch(
        "agent.whatweb_utils.run_whatweb_scan", return_value=mock_ip_whatweb_output
    )

    result = tools.fingerprint(target="https://192.168.0.76:443")

    assert len(result) == 16
    fingerprint_names = [fp.name for fp in result]
    assert "lighttpd" in fingerprint_names
    assert "JQuery" in fingerprint_names


def testFingerprint_whenScanFails_returnsEmptyResult(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint handles scan failures gracefully."""
    mocker.patch(
        "agent.whatweb_utils.run_whatweb_scan",
        side_effect=subprocess.CalledProcessError(1, "cmd"),
    )

    result = tools.fingerprint(target="https://ostorlab.co:443")

    assert len(result) == 0


def testFingerprint_whenEmptyOutput_returnsEmptyFingerprints(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint handles empty output gracefully."""
    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=b"")

    result = tools.fingerprint(target="https://ostorlab.co:443")

    assert len(result) == 0


def testParseWhatWebOutput_whenVersionIsList_extractsAllVersions() -> None:
    """Test parse_whatweb_output handles version arrays correctly."""
    test_output = (
        b'["http://test.com",200,[["Bootstrap",[{"version":["3.0.3","3.1.0"]}]]]]'
    )

    fingerprint_dicts = whatweb_utils.parse_whatweb_output(test_output)

    assert len(fingerprint_dicts) == 2
    assert fingerprint_dicts[0]["name"] == "Bootstrap"
    assert fingerprint_dicts[0]["version"] == "3.0.3"
    assert fingerprint_dicts[1]["name"] == "Bootstrap"
    assert fingerprint_dicts[1]["version"] == "3.1.0"


def testParseWhatWebOutput_whenStringPresent_usesStringAsName() -> None:
    """Test parse_whatweb_output uses string field as library name when present."""
    test_output = b'["http://test.com",200,[["HTTPServer",[{"string":"nginx","version":"1.18.0"}]]]]'

    fingerprint_dicts = whatweb_utils.parse_whatweb_output(test_output)

    assert len(fingerprint_dicts) == 1
    assert fingerprint_dicts[0]["name"] == "nginx"
    assert fingerprint_dicts[0]["version"] == "1.18.0"
