"""Unittests for fingerprint MCP server."""

import pathlib
import subprocess

import pytest
from pytest_mock import plugin

from agent import definitions
from agent import whatweb_utils
from agent.mcp_server.tools import fingerprint as fingerprint_tool


def testFingerprint_whenTargetIsValid_returnsFingerprints(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint with valid target returns fingerprints correctly."""
    with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
        mock_output = op.read()

    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=mock_output)

    result = fingerprint_tool.fingerprint(target="ostorlab.co")

    assert result.target_url == "https://ostorlab.co:443"
    assert len(result.fingerprints) > 0
    assert any(fp.name == "Google-Analytics" for fp in result.fingerprints)
    assert any(
        fp.name == "Google-Analytics" and fp.version == "Universal"
        for fp in result.fingerprints
    )
    assert any(fp.type == "BACKEND_COMPONENT" for fp in result.fingerprints)


def testFingerprint_whenTargetIsURL_parsesCorrectly(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint with full URL target."""
    with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
        mock_output = op.read()

    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=mock_output)

    result = fingerprint_tool.fingerprint(target="http://ostorlab.co:80")

    assert result.target_url == "http://ostorlab.co:80"
    assert len(result.fingerprints) > 0


def testFingerprint_whenSchemeIsHttp_usesPort80(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint uses correct default port for http."""
    with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
        mock_output = op.read()

    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=mock_output)

    result = fingerprint_tool.fingerprint(target="ostorlab.co", scheme="http")

    assert result.target_url == "http://ostorlab.co:80"


def testFingerprint_whenSchemeIsHttps_usesPort443(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint uses correct default port for https."""
    with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
        mock_output = op.read()

    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=mock_output)

    result = fingerprint_tool.fingerprint(target="ostorlab.co", scheme="https")

    assert result.target_url == "https://ostorlab.co:443"


def testFingerprint_whenCustomPort_usesCustomPort(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint uses custom port when specified."""
    with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
        mock_output = op.read()

    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=mock_output)

    result = fingerprint_tool.fingerprint(
        target="ostorlab.co", port=8080, scheme="http"
    )

    assert result.target_url == "http://ostorlab.co:8080"


def testFingerprint_whenBlacklistedPlugins_filtersThemOut(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint filters out blacklisted plugins."""
    with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
        mock_output = op.read()

    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=mock_output)

    result = fingerprint_tool.fingerprint(target="ostorlab.co")

    assert not any(
        fp.name in definitions.BLACKLISTED_PLUGINS for fp in result.fingerprints
    )


def testFingerprint_whenIPTarget_scansSuccessfully(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint with IP address target."""
    with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
        mock_output = op.read()

    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=mock_output)

    result = fingerprint_tool.fingerprint(target="192.168.0.76")

    assert result.target_url == "https://192.168.0.76:443"
    assert len(result.fingerprints) > 0
    assert any("lighttpd" in fp.name for fp in result.fingerprints)


def testFingerprint_whenScanFails_returnsEmptyResult(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint handles scan failures gracefully."""
    mocker.patch(
        "agent.whatweb_utils.run_whatweb_scan",
        side_effect=subprocess.CalledProcessError(1, "cmd"),
    )

    result = fingerprint_tool.fingerprint(target="ostorlab.co")

    assert result.target_url == "ostorlab.co"
    assert len(result.fingerprints) == 0


def testFingerprint_whenUnsupportedScheme_raisesValueError(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint raises ValueError for unsupported schemes."""
    with pytest.raises(ValueError, match="Unsupported scheme"):
        fingerprint_tool.fingerprint(target="ostorlab.co", scheme="ftp")


def testFingerprint_whenEmptyOutput_returnsEmptyFingerprints(
    mocker: plugin.MockerFixture,
) -> None:
    """Test fingerprint handles empty output gracefully."""
    mocker.patch("agent.whatweb_utils.run_whatweb_scan", return_value=b"")

    result = fingerprint_tool.fingerprint(target="ostorlab.co")

    assert result.target_url == "https://ostorlab.co:443"
    assert len(result.fingerprints) == 0


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


def testNormalizeTarget_whenTargetIsURL_returnsUnchanged() -> None:
    """Test normalize_target preserves valid URLs."""
    url = "https://example.com:8080"

    result = whatweb_utils.normalize_target(url)

    assert result == url


def testNormalizeTarget_whenSchemeAndPort_buildsCorrectURL() -> None:
    """Test normalize_target builds URL with scheme and port."""
    result = whatweb_utils.normalize_target("example.com", port=8080, scheme="http")

    assert result == "http://example.com:8080"


def testNormalizeTarget_whenOnlyScheme_buildsURLWithoutPort() -> None:
    """Test normalize_target builds URL with just scheme."""
    result = whatweb_utils.normalize_target("example.com", scheme="https")

    assert result == "https://example.com"
