"""Unittests for whatweb agent."""

import pathlib
import subprocess
import tempfile
from typing import Any

import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import whatweb_agent


def testWhatWebAgent_withDomainMsgAndAllChecksEnabled_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    detail = (
        "Found fingerprint `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in target "
        "`ostorlab.co`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(domain_msg)
            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("port") == 443
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("schema") == "https"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "Google-Analytics"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "Universal"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )


def testWhatWebAgent_withLinkMsgAndAllChecksEnabled_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    link_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    The test also ensures the correct compute of the port and schema from the target link.
    """
    detail = (
        "Found fingerprint `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in target "
        "`ostorlab.co`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(link_msg)
            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("port") == 80 for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("schema") == "http"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "Google-Analytics"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "Universal"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )


def testWhatWebAgent_whenDomainMsgHasPortAndSchema_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    domain_msg_with_port_and_schema: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target domain, with the port and schema present.
    The tests mocks the call to WhatWeb binary and validates the parsing and sending the findings to the queue.
    """
    detail = (
        "Found fingerprint `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in target "
        "`ostorlab.co`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(domain_msg_with_port_and_schema)
            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("port") == 80 for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("schema") == "http"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "Google-Analytics"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "Universal"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )


def testWhatWebAgent_withIpMsgAndAllChecksEnabled_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    ip_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    detail = (
        "Found fingerprint `lighttpd`, version `1.4.28`, of type `BACKEND_COMPONENT` in target "
        "`192.168.0.76`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg)
            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("port") == 443
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("host") == "192.168.0.76"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "lighttpd/1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )


def testWhatWebAgent_withIpv6MsgAndAllChecksEnabled_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    ipv6_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target IPv6 address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    detail = (
        "Found fingerprint `lighttpd`, version `1.4.28`, of type `BACKEND_COMPONENT` in target "
        "`2a00:1450:4006:80c::2004`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ipv6_msg)
            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("port") == 443
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("host") == "2a00:1450:4006:80c::2004"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "lighttpd/1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )


def testWhatWebAgent_whenIpMsgHasPortAndSchema_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    ip_msg_with_port_and_schema: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address, with the port and protocol present in the message.
    The tests mocks the call to WhatWeb binary  and validates the parsing and sending the findings to the queue.
    """
    detail = (
        "Found fingerprint `lighttpd`, version `1.4.28`, of type `BACKEND_COMPONENT` in target "
        "`192.168.0.0`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg_with_port_and_schema)
            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("port") == 80 for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("host") == "192.168.0.0"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "lighttpd/1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )


def testAgentWhatWeb_whenAssetAlreadyScaned_doNothing(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure whatweb agent does not process the same message multiple times."""
    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(domain_msg)
            count_first = len(agent_mock)
            whatweb_test_agent.process(domain_msg)
            count_second = len(agent_mock)
            assert count_second - count_first == 0


def testWhatWebAgent_whenIpMsgHasPortAndSchemaAndMask_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    ip_msg_with_port_schema_mask: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address, with the port and protocol present in the message.
    The tests mocks the call to WhatWeb binary  and validates the parsing and sending the findings to the queue.
    """
    detail = (
        "Found fingerprint `lighttpd`, version `1.4.28`, of type `BACKEND_COMPONENT` in target "
        "`192.168.0.0`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 52
            assert any(
                fingerprint_msg.data.get("port") == 80 for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("host") == "192.168.0.0"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "lighttpd/1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "1.4.28"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 52


def testWhatWebAgent_whenWhatWebReturnsError_ContinueProcessing(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    ip_msg_with_port_schema_mask: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address, with the port and protocol present in the message.
    The tests mocks the call to WhatWeb binary and handles the case where whatweb returns an error.
    """

    subprocess_mocker = mocker.patch("subprocess.run")
    subprocess_mocker.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd="cmd"
    )
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 0
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 0


def testWhatWebAgent_withIpMsgAndAllChecksEnabled_emitsFingerprintsWithlocation(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    ip_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    subprocess_mock = mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_test_agent.process(ip_msg)

            assert len(agent_mock) > 0
            fp_location = {
                "ipv4": {"host": "192.168.0.76", "mask": "32", "version": 4},
                "metadata": [{"value": "443", "type": "PORT"}],
            }
            assert any(
                fingerprint.data.get("vulnerability_location") == fp_location
                for fingerprint in agent_mock
            )
            assert (
                subprocess_mock.mock_calls[0].args[0][2] == "https://192.168.0.76:443"
            )


def testWhatWebAgent_withDomainMsgAndAllChecksEnabled_emitsFingerprintsWithlocation(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    subprocess_mock = mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_test_agent.process(domain_msg)

            assert len(agent_mock) > 0
            fp_location = {
                "domain_name": {
                    "name": "ostorlab.co",
                },
                "metadata": [{"value": "443", "type": "PORT"}],
            }
            assert any(
                fingerprint.data.get("vulnerability_location") == fp_location
                for fingerprint in agent_mock
            )
            assert subprocess_mock.mock_calls[0].args[0][2] == "https://ostorlab.co:443"


def testWhatWebAgent_withDomainScopeArgAndLinkMessageInScope_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_agent_with_scope_arg: whatweb_agent.AgentWhatWeb,
    link_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the domain scope argument is enforced, and urls in the scope should be scanned."""
    detail = (
        "Found fingerprint `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in target "
        "`ostorlab.co`"
    )
    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_agent_with_scope_arg.process(link_msg)

            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("schema") == "http"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "Google-Analytics"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )


def testWhatWebAgent_withDomainScopeArgAndLinkMessageNotInScope_targetShouldNotBeScanned(
    agent_mock: list[message.Message],
    whatweb_agent_with_scope_arg: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure the domain scope argument is enforced, and urls not in the scope should not be scanned."""
    input_selector = "v3.asset.link"
    input_data = {"url": "http://support.google.co", "method": "GET"}
    link_msg = message.Message.from_data(selector=input_selector, data=input_data)

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_agent_with_scope_arg.process(link_msg)

            assert len(agent_mock) == 0


def testWhatWebAgent_withUnsupportedSchema_targetShouldNotBeScanned(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure when the schema is not supported, the target should not be scanned."""
    # prepare
    input_selector = "v3.asset.link"
    input_data = {"url": "mailto://me@google.com", "method": "GET"}
    link_msg = message.Message.from_data(selector=input_selector, data=input_data)
    subprocess_mock = mocker.patch("subprocess.run", return_value=None)

    # act
    whatweb_test_agent.process(link_msg)

    # assert
    assert len(agent_mock) == 0
    assert subprocess_mock.call_count == 0


def testWhatWebAgent_whenIPv4AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
    scan_message_ipv4_with_mask16: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV4 and the Limit is not reached."""
    mocker.patch(
        "ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.add_ip_network",
        return_value=False,
    )

    test_agent.process(scan_message_ipv4_with_mask16)


def testWhatWebAgent_whenIPv6AssetReachCIDRLimit_raiseValueError(
    test_agent: whatweb_agent.AgentWhatWeb,
    scan_message_ipv6_with_mask64: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV6 and the Limit is reached."""
    with pytest.raises(ValueError, match="Subnet mask below 112 is not supported."):
        test_agent.process(scan_message_ipv6_with_mask64)


def testWhatWebAgent_whenIPv6AssetDoesNotReachCIDRLimit_doesNotRaiseValueError(
    test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
    scan_message_ipv6_with_mask112: message.Message,
) -> None:
    """Test the CIDR Limit in case IPV6 and the Limit is not reached."""
    mocker.patch(
        "ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.add_ip_network",
        return_value=False,
    )

    test_agent.process(scan_message_ipv6_with_mask112)


def testWhatWebAgent_whenIPAssetHasIncorrectVersion_raiseValueError(
    test_agent: whatweb_agent.AgentWhatWeb,
    scan_message_ipv_with_incorrect_version: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the CIDR Limit in case IP has incorrect version."""
    mocker.patch.object(test_agent, "_should_target_be_processed", return_value=True)

    def mock_prepare_ip_targets(m: message.Message) -> list[Any]:
        version = m.data.get("version")
        if version not in (4, 6):
            raise ValueError(f"Incorrect ip version {version}.")
        return []

    mocker.patch.object(
        test_agent, "_prepare_ip_targets", side_effect=mock_prepare_ip_targets
    )

    with pytest.raises(ValueError, match="Incorrect ip version 5."):
        test_agent.process(scan_message_ipv_with_incorrect_version)


def testWhatWebAgent_whenSchemeIsNotHTTP_defaultToNoScheme(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    ip_tcp_message: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    run_mock = mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/ip_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_tcp_message)

            assert run_mock.call_count == 1
            call_args = run_mock.call_args[0][0]
            assert call_args[0] == "./whatweb"
            assert call_args[1].startswith("--log-json-verbose=")
            assert call_args[2] == "192.168.0.0:80"


def testWhatWebAgent_withIPv4AndMaskButNoVersion_shouldHandleVersionCorrectly(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
) -> None:
    """Ensure when receiving an IPv4 address with mask but no version specified,
    the agent handles it correctly by inferring the version."""
    input_selector = "v3.asset.ip.v4"
    input_data = {"host": "80.121.155.176", "mask": "29"}
    ip_msg = message.Message.from_data(selector=input_selector, data=input_data)

    subprocess_mock = mocker.patch(
        "subprocess.run",
        return_value=mocker.Mock(stdout=b'{"target":"test","results":[]}'),
    )

    mock_temp_file = mocker.Mock()
    mock_temp_file.read.return_value = b'{"target":"test","results":[]}'
    mock_temp_file.name = "mock_file"
    mock_tempfile = mocker.patch("tempfile.NamedTemporaryFile")
    mock_tempfile.return_value.__enter__.return_value = mock_temp_file

    whatweb_test_agent.process(ip_msg)

    assert (
        subprocess_mock.call_count == 6
    )  # Should have scanned 6 IPs in the /29 network

    expected_ips = [
        "80.121.155.177",
        "80.121.155.178",
        "80.121.155.179",
        "80.121.155.180",
        "80.121.155.181",
        "80.121.155.182",
    ]

    calls = subprocess_mock.call_args_list
    assert len(calls) == len(expected_ips)

    for call, expected_ip in zip(calls, expected_ips):
        args, kwargs = call
        command = args[0]
        assert any(expected_ip in arg for arg in command), (
            f"Expected IP {expected_ip} not found in command {command}"
        )


def testWhatWebAgent_whenInvalidIPAddressIsProvided_raisesValueError(
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that a ValueError is raised when an invalid IP address is provided."""
    input_selector = "v3.asset.ip.v4"
    input_data = {"host": "invalid_ip", "mask": "24"}
    ip_msg = message.Message.from_data(selector=input_selector, data=input_data)

    with pytest.raises(ValueError, match="Invalid IP address: invalid_ip"):
        whatweb_test_agent.process(ip_msg)


def testWhatWebAgent_withSAPNetWeaverDetection_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a target that has SAP NetWeaver server.
    The test mocks the call to WhatWeb binary and validates the parsing and
    emission of SAP NetWeaver fingerprint findings.
    """
    detail = (
        "Found fingerprint `SAP NetWeaver`, version `7.45`, of type `BACKEND_COMPONENT` in target "
        "`ostorlab.co`"
    )
    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/sap_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_test_agent.process(domain_msg)

            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("library_name") == "SAP NetWeaver"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "7.45"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )


def testWhatWebAgent_withCiscoBroadWorksDetection_emitsFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent with a target that has Cisco BroadWorks server.
    The test mocks the call to WhatWeb binary and validates the parsing and
    emission of Cisco BroadWorks fingerprint findings.
    """
    detail = (
        "Found fingerprint `Cisco BroadWorks`, version `22.0`, of type `BACKEND_COMPONENT` in target "
        "`ostorlab.co`"
    )

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(
            f"{pathlib.Path(__file__).parent}/broadworks_output.json", "rb"
        ) as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_test_agent.process(domain_msg)

            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("library_name") == "Cisco BroadWorks"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_version") == "22.0"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )


def testWhatWebAgent_withLinkMsgDetectsPlex_emitsPlexFingerprints(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    link_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test the whatweb agent detection of Plex Media Server via link message.
    The tests mocks the call to WhatWeb binary and validates the parsing
    and sending the Plex fingerprint findings to the queue with correct port/schema extraction.
    """
    detail = "Found fingerprint `Plex Media Server` of type `BACKEND_COMPONENT` in target `ostorlab.co`"

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/plex_output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_test_agent.process(link_msg)

            assert len(agent_mock) > 0
            assert any(
                fingerprint_msg.data.get("port") == 80 for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("schema") == "http"
                for fingerprint_msg in agent_mock
            )
            assert any(
                fingerprint_msg.data.get("library_name") == "Plex Media Server"
                for fingerprint_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("title") == "Tech Stack Fingerprint"
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("risk_rating") == "INFO" for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("technical_detail") == detail
                for vuln_msg in agent_mock
            )
            assert any(
                vuln_msg.data.get("security_issue") is True for vuln_msg in agent_mock
            )


def testWhatWebAgent_whenMCPServerDisabled_startDoesNothing(
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that start method does nothing when MCP server is disabled."""
    mcp_run_mock = mocker.patch("agent.mcp_server.mcp_runner.MCPRunner.run")

    whatweb_test_agent.start()

    assert mcp_run_mock.call_count == 0


def testWhatWebAgent_whenMCPServerEnabled_startsServerAndSkipsProcessing(
    whatweb_agent_with_mcp_server: whatweb_agent.AgentWhatWeb,
    agent_mock: list[message.Message],
    domain_msg: message.Message,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that when MCP server is enabled, start method starts server and process returns None."""
    mcp_run_mock = mocker.patch("agent.mcp_server.mcp_runner.MCPRunner.run")

    whatweb_agent_with_mcp_server.start()

    assert mcp_run_mock.call_count == 1
    whatweb_agent_with_mcp_server.process(domain_msg)
    assert len(agent_mock) == 0


def testWhatWebAgent_whenUrlHasTrailingColon_shouldNotFail(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that the agent handles URLs with trailing colons without crashing."""
    input_selector = "v3.asset.link"
    input_data = {"url": "http://example.com:", "method": "GET"}
    link_msg = message.Message.from_data(selector=input_selector, data=input_data)

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_test_agent.process(link_msg)

            assert len(agent_mock) > 0
            assert any(msg.data.get("name") == "example.com" for msg in agent_mock)


def testWhatWebAgent_whenUrlHasInvalidPort_shouldNotFail(
    agent_mock: list[message.Message],
    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
    mocker: plugin.MockerFixture,
) -> None:
    """Test that the agent handles URLs with invalid ports without crashing."""
    input_selector = "v3.asset.link"
    input_data = {"url": "http://example.com:abc", "method": "GET"}
    link_msg = message.Message.from_data(selector=input_selector, data=input_data)

    mocker.patch("subprocess.run", return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch("tempfile.NamedTemporaryFile", return_value=fp)
        with open(f"{pathlib.Path(__file__).parent}/output.json", "rb") as op:
            fp.write(op.read())
            fp.seek(0)

            whatweb_test_agent.process(link_msg)

            assert len(agent_mock) > 0
            assert any(msg.data.get("name") == "example.com" for msg in agent_mock)
