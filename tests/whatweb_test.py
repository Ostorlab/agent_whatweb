"""Unittests for whatweb agent."""
from typing import List
import pathlib
import tempfile
import subprocess

from pytest_mock import plugin
from ostorlab.agent.message import message

from agent import whatweb_agent


def testWhatWebAgent_withDomainMsgAndAllChecksEnabled_emitsFingerprints(agent_mock: List[message.Message],
                                                                        whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                                        domain_msg: message.Message,
                                                                        mocker: plugin.MockerFixture) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    detail = 'Found library `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in target ' \
             '`ostorlab.co`'

    mocker.patch('subprocess.run', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(domain_msg)
            assert len(agent_mock) > 0
            assert any(fingerprint_msg.data.get('port') == 443 for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('schema') == 'https' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_name') == 'Google-Analytics' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_version') == 'Universal' for fingerprint_msg in agent_mock)
            assert any(vuln_msg.data.get('title') == 'Tech Stack Fingerprint' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('risk_rating') == 'INFO' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('technical_detail') == detail for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('security_issue') is True for vuln_msg in agent_mock)


def testWhatWebAgent_withLinkMsgAndAllChecksEnabled_emitsFingerprints(agent_mock: List[message.Message],
                                                                      whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                                      link_msg: message.Message,
                                                                      mocker: plugin.MockerFixture) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    The test also ensures the correct compute of the port and schema from the target link.
    """
    detail = 'Found library `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in target ' \
             '`ostorlab.co`'

    mocker.patch('subprocess.run', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(link_msg)
            assert len(agent_mock) > 0
            assert any(fingerprint_msg.data.get('port') == 80 for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('schema') == 'http' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_name') == 'Google-Analytics' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_version') == 'Universal' for fingerprint_msg in agent_mock)
            assert any(vuln_msg.data.get('title') == 'Tech Stack Fingerprint' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('risk_rating') == 'INFO' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('technical_detail') == detail for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('security_issue') is True for vuln_msg in agent_mock)


def testWhatWebAgent_whenDomainMsgHasPortAndSchema_emitsFingerprints(agent_mock: List[message.Message],
                                                                     whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                                     domain_msg_with_port_and_schema: message.Message,
                                                                     mocker: plugin.MockerFixture) -> None:
    """Test the whatweb agent with a given target domain, with the port and schema present.
    The tests mocks the call to WhatWeb binary and validates the parsing and sending the findings to the queue.
    """
    detail = 'Found library `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in target ' \
             '`ostorlab.co`'

    mocker.patch('subprocess.run', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(domain_msg_with_port_and_schema)
            assert len(agent_mock) > 0
            assert any(fingerprint_msg.data.get('port') == 80 for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('schema') == 'http' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_name') == 'Google-Analytics' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_version') == 'Universal' for fingerprint_msg in agent_mock)
            assert any(vuln_msg.data.get('title') == 'Tech Stack Fingerprint' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('risk_rating') == 'INFO' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('technical_detail') == detail for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('security_issue') is True for vuln_msg in agent_mock)


def testWhatWebAgent_withIpMsgAndAllChecksEnabled_emitsFingerprints(agent_mock: List[message.Message],
                                                                    whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                                    ip_msg: message.Message,
                                                                    mocker: plugin.MockerFixture) -> None:
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    detail = 'Found library `lighttpd`, version `1.4.28`, of type `BACKEND_COMPONENT` in target ' \
             '`192.168.0.76`'

    mocker.patch('subprocess.run', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/ip_output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg)
            assert len(agent_mock) > 0
            assert any(fingerprint_msg.data.get('port') == 443 for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('schema') == 'https' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_name') == 'lighttpd/1.4.28' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_version') == '1.4.28' for fingerprint_msg in agent_mock)
            assert any(vuln_msg.data.get('title') == 'Tech Stack Fingerprint' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('risk_rating') == 'INFO' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('technical_detail') == detail for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('security_issue') is True for vuln_msg in agent_mock)


def testWhatWebAgent_whenIpMsgHasPortAndSchema_emitsFingerprints(agent_mock: List[message.Message],
                                                                 whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                                 ip_msg_with_port_and_schema: message.Message,
                                                                 mocker: plugin.MockerFixture) -> None:
    """Test the whatweb agent with a given target address, with the port and protocol present in the message.
    The tests mocks the call to WhatWeb binary  and validates the parsing and sending the findings to the queue.
    """
    detail = 'Found library `lighttpd`, version `1.4.28`, of type `BACKEND_COMPONENT` in target ' \
             '`192.168.0.0`'

    mocker.patch('subprocess.run', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/ip_output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg_with_port_and_schema)
            assert len(agent_mock) > 0
            assert any(fingerprint_msg.data.get('port') == 80 for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('schema') == 'http' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_name') == 'lighttpd/1.4.28' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_version') == '1.4.28' for fingerprint_msg in agent_mock)
            assert any(vuln_msg.data.get('title') == 'Tech Stack Fingerprint' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('risk_rating') == 'INFO' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('technical_detail') == detail for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('security_issue') is True for vuln_msg in agent_mock)


def testAgentWhatWeb_whenAssetAlreadyScaned_doNothing(agent_mock: List[message.Message],
                                                      whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                      domain_msg: message.Message,
                                                      mocker: plugin.MockerFixture) -> None:
    """Ensure whatweb agent does not process the same message multiple times."""
    mocker.patch('subprocess.run', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(domain_msg)
            count_first = len(agent_mock)
            whatweb_test_agent.process(domain_msg)
            count_second = len(agent_mock)
            assert count_second - count_first == 0


def testWhatWebAgent_whenIpMsgHasPortAndSchemaAndMask_emitsFingerprints(agent_mock: List[message.Message],
                                                                        whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                                        ip_msg_with_port_schema_mask: message.Message,
                                                                        ip_msg_with_port_schema_mask_2: message.Message,
                                                                        mocker: plugin.MockerFixture) -> None:
    """Test the whatweb agent with a given target address, with the port and protocol present in the message.
    The tests mocks the call to WhatWeb binary  and validates the parsing and sending the findings to the queue.
    """
    detail = 'Found library `lighttpd`, version `1.4.28`, of type `BACKEND_COMPONENT` in target ' \
             '`192.168.0.0`'

    mocker.patch('subprocess.run', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/ip_output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 52
            assert any(fingerprint_msg.data.get('port') == 80 for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('schema') == 'http' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_name') == 'lighttpd/1.4.28' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_version') == '1.4.28' for fingerprint_msg in agent_mock)
            assert any(vuln_msg.data.get('title') == 'Tech Stack Fingerprint' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('risk_rating') == 'INFO' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('technical_detail') == detail for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('security_issue') is True for vuln_msg in agent_mock)
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/ip_output.json', 'rb') as op:
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 52


def testWhatWebAgent_whenWhatWebReturnsError_ContinueProcessing(agent_mock: List[message.Message],
                                                                whatweb_test_agent: whatweb_agent.AgentWhatWeb,
                                                                ip_msg_with_port_schema_mask: message.Message,
                                                                ip_msg_with_port_schema_mask_2: message.Message,
                                                                mocker: plugin.MockerFixture) -> None:
    """Test the whatweb agent with a given target address, with the port and protocol present in the message.
    The tests mocks the call to WhatWeb binary and handles the case where whatweb returns an error.
    """

    subprocess_mocker = mocker.patch('subprocess.run')
    subprocess_mocker.side_effect = subprocess.CalledProcessError(returncode=1, cmd='cmd')
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/ip_output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 0
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/ip_output.json', 'rb') as op:
            whatweb_test_agent.process(ip_msg_with_port_schema_mask)
            assert len(agent_mock) == 0
