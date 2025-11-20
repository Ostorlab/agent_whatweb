"""Unit tests for whatweb_utils module."""

import subprocess

import pytest
from pytest_mock import plugin

from agent import whatweb_utils


def testNormalizeTarget_whenTargetHasPath_buildsCorrectURL() -> None:
    """Test normalize_target handles paths correctly."""
    result = whatweb_utils.normalize_target("example.com/path/to/page", scheme="http")

    assert result == "http://example.com/path/to/page"


def testNormalizeTarget_whenTargetHasPathAndPort_buildsCorrectURL() -> None:
    """Test normalize_target handles paths and ports correctly."""
    result = whatweb_utils.normalize_target(
        "example.com/path", port=8080, scheme="http"
    )

    assert result == "http://example.com:8080/path"


def testNormalizeTarget_whenDefaultScheme_usesHttps() -> None:
    """Test normalize_target defaults to https."""
    result = whatweb_utils.normalize_target("example.com")

    assert result == "https://example.com"


def testParseWhatWebOutput_whenEmptyBytes_returnsEmptyList() -> None:
    """Test parse_whatweb_output handles empty input."""
    result = whatweb_utils.parse_whatweb_output(b"")

    assert result == []


def testParseWhatWebOutput_whenInvalidJSON_returnsEmptyList() -> None:
    """Test parse_whatweb_output handles invalid JSON."""
    result = whatweb_utils.parse_whatweb_output(b"not valid json")

    assert result == []


def testParseWhatWebOutput_whenShortList_skipsEntry() -> None:
    """Test parse_whatweb_output skips malformed entries."""
    test_output = b'["http://test.com",200]'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert result == []


def testParseWhatWebOutput_whenPluginEntryTooShort_skipsPlugin() -> None:
    """Test parse_whatweb_output skips malformed plugin entries."""
    test_output = b'["http://test.com",200,[["OnlyName"]]]'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert result == []


def testParseWhatWebOutput_whenPluginNameNotString_skipsPlugin() -> None:
    """Test parse_whatweb_output skips non-string plugin names."""
    test_output = b'["http://test.com",200,[[123,[{"version":"1.0"}]]]]'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert result == []


def testParseWhatWebOutput_whenPluginDataNotList_skipsPlugin() -> None:
    """Test parse_whatweb_output handles non-list plugin entries."""
    test_output = b'["http://test.com",200,["NotAList"]]'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert result == []


def testParseWhatWebOutput_whenVersionIsString_convertsToString() -> None:
    """Test parse_whatweb_output handles non-list version."""
    test_output = b'["http://test.com",200,[["nginx",[{"version":123}]]]]'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert len(result) == 1
    assert result[0]["version"] == "123"


def testParseWhatWebOutput_whenNoVersionData_returnsNoneVersion() -> None:
    """Test parse_whatweb_output handles missing version."""
    test_output = b'["http://test.com",200,[["nginx",[{"other":"data"}]]]]'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert len(result) == 1
    assert result[0]["name"] == "nginx"
    assert result[0]["version"] is None


def testParseWhatWebOutput_whenMultipleLines_parsesAll() -> None:
    """Test parse_whatweb_output handles multiple JSON lines."""
    test_output = (
        b'["http://test1.com",200,[["nginx",[{"version":"1.0"}]]]]\n'
        b'["http://test2.com",200,[["apache",[{"version":"2.0"}]]]]'
    )

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert len(result) == 2
    assert result[0]["name"] == "nginx"
    assert result[1]["name"] == "apache"


def testParseWhatWebOutput_whenEmptyPluginData_stillAddsEntry() -> None:
    """Test parse_whatweb_output handles plugins with empty metadata."""
    test_output = b'["http://test.com",200,[["nginx",[]]]]'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert len(result) == 1
    assert result[0]["name"] == "nginx"
    assert result[0]["version"] is None


def testParseWhatWebOutput_whenOnlyStringInMetadata_usesAsName() -> None:
    """Test parse_whatweb_output uses string field as name."""
    test_output = (
        b'["http://test.com",200,[["HTTPServer",[{"string":"CustomServer"}]]]]'
    )

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert len(result) == 1
    assert result[0]["name"] == "CustomServer"


def testParseWhatWebOutput_whenVersionAndString_usesBoth() -> None:
    """Test parse_whatweb_output uses both version and string."""
    test_output = (
        b'["http://test.com",200,[["HTTPServer",'
        b'[{"string":"nginx","version":"1.18.0"}]]]]'
    )

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert len(result) == 1
    assert result[0]["name"] == "nginx"
    assert result[0]["version"] == "1.18.0"


def testParseWhatWebOutput_whenScanResultNotList_skipsResult() -> None:
    """Test parse_whatweb_output skips non-list scan results."""
    test_output = b'{"not": "a list"}'

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert result == []


def testParseWhatWebOutput_whenMultipleMetadataEntries_parsesAll() -> None:
    """Test parse_whatweb_output handles multiple metadata entries."""
    test_output = (
        b'["http://test.com",200,[["nginx",'
        b'[{"version":"1.0"},{"other":"data"},{"version":"2.0"}]]]]'
    )

    result = whatweb_utils.parse_whatweb_output(test_output)

    assert len(result) == 2
    assert result[0]["version"] == "1.0"
    assert result[1]["version"] == "2.0"


def testNormalizeTarget_whenURLWithUnsupportedScheme_raisesValueError() -> None:
    """Test normalize_target raises error for unsupported URL scheme."""
    with pytest.raises(ValueError, match="Unsupported scheme: ftp"):
        whatweb_utils.normalize_target("ftp://example.com")


def testNormalizeTarget_whenSchemeUnsupported_raisesValueError() -> None:
    """Test normalize_target raises error for unsupported scheme parameter."""
    with pytest.raises(ValueError, match="Unsupported scheme: ftp"):
        whatweb_utils.normalize_target("example.com", scheme="ftp")


def testRunWhatWebScan_whenFileDoesNotExist_doesNotCallUnlink(
    mocker: plugin.MockerFixture,
) -> None:
    """Test run_whatweb_scan skips unlink when file doesn't exist."""
    mocker.patch("subprocess.run")
    mock_temp = mocker.patch("tempfile.NamedTemporaryFile")
    mock_temp.return_value.__enter__.return_value.name = "/tmp/test"
    mocker.patch("builtins.open", mocker.mock_open(read_data=b"test"))
    mocker.patch("os.path.exists", return_value=False)
    mock_unlink = mocker.patch("os.unlink")

    result = whatweb_utils.run_whatweb_scan("https://example.com")

    assert result == b"test"
    assert mock_unlink.call_count == 0


def testRunWhatWebScan_whenSubprocessFails_cleansUpFile(
    mocker: plugin.MockerFixture,
) -> None:
    """Test run_whatweb_scan cleans up file even when subprocess fails."""
    mocker.patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "cmd"))
    mock_temp = mocker.patch("tempfile.NamedTemporaryFile")
    mock_temp.return_value.__enter__.return_value.name = "/tmp/test"
    mocker.patch("os.path.exists", return_value=True)
    mock_unlink = mocker.patch("os.unlink")

    with pytest.raises(subprocess.CalledProcessError):
        whatweb_utils.run_whatweb_scan("https://example.com")

    assert mock_unlink.call_count == 1
