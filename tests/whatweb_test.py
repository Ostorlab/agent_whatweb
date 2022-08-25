"""Unittests for whatweb agent."""
import pathlib
import tempfile


def testWhatWebAgent_withDomainMsgAndAllChecksEnabled_emitsFingerprints(agent_mock, whatweb_test_agent,
                                                                        domain_msg, mocker):
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


def testWhatWebAgent_withLinkMsgAndAllChecksEnabled_emitsFingerprints(agent_mock, whatweb_test_agent, link_msg, mocker):
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


def testWhatWebAgent_whenDomainMsgHasPortAndSchema_emitsFingerprints(agent_mock, whatweb_test_agent,
                                                                        domain_msg_with_port_and_schema, mocker):
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


def testWhatWebAgent_withIpMsgAndAllChecksEnabled_emitsFingerprints(agent_mock, whatweb_test_agent,
                                                                        ip_msg, mocker):
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


def testWhatWebAgent_whenIpMsgHasPortAndSchema_emitsFingerprints(agent_mock, whatweb_test_agent,
                                                                        ip_msg_with_port_and_schema, mocker):
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
            for vuln_msg in agent_mock:
                print('Vulnz ', vuln_msg.data)
            assert len(agent_mock) > 0
            assert any(fingerprint_msg.data.get('port') == 80 for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('schema') == 'http' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_name') == 'lighttpd/1.4.28' for fingerprint_msg in agent_mock)
            assert any(fingerprint_msg.data.get('library_version') == '1.4.28' for fingerprint_msg in agent_mock)
            assert any(vuln_msg.data.get('title') == 'Tech Stack Fingerprint' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('risk_rating') == 'INFO' for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('technical_detail') == detail for vuln_msg in agent_mock)
            assert any(vuln_msg.data.get('security_issue') is True for vuln_msg in agent_mock)


def testAgentWhatWeb_whenAssetAlreadyScaned_doNothing(agent_mock, whatweb_test_agent,
                                                      domain_msg, mocker):
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
