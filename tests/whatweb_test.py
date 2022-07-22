"""Unittests for whatweb agent."""
import pathlib
import tempfile


def testWhatWebAgent_withDomainMsgAndAllChecksEnabled_emitsFingerprints(agent_mock, whatweb_test_agent,
                                                                        domain_msg, mocker):
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    """
    del agent_mock
    detail = 'Found library `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in domain ' \
             '`ostorlab.co`'
    output_selector = 'v3.fingerprint.domain_name.service.library'
    output_data = {
        'name': 'ostorlab.co',
        'port': 443,
        'schema': 'https',
        'library_name': 'Google-Analytics',
        'library_version': 'Universal',
        'library_type': 'BACKEND_COMPONENT',
        'detail': detail
    }

    mocker.patch('subprocess.run', return_value=None)
    mock_emit = mocker.patch('agent.whatweb_agent.AgentWhatWeb.emit', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(domain_msg)
            mock_emit.assert_any_call(selector=output_selector, data=output_data)


def testWhatWebAgent_withLinkMsgAndAllChecksEnabled_emitsFingerprints(agent_mock, whatweb_test_agent, link_msg, mocker):
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue.
    The test also ensures the correct compute of the port and schema from the target link.
    """
    del agent_mock

    detail = 'Found library `Google-Analytics`, version `Universal`, of type `BACKEND_COMPONENT` in domain ' \
             '`ostorlab.co`'
    output_selector = 'v3.fingerprint.domain_name.service.library'
    output_data = {
        'name': 'ostorlab.co',
        'port': 80,
        'schema': 'http',
        'library_name': 'Google-Analytics',
        'library_version': 'Universal',
        'library_type': 'BACKEND_COMPONENT',
        'detail': detail
    }

    mocker.patch('subprocess.run', return_value=None)
    mock_emit = mocker.patch('agent.whatweb_agent.AgentWhatWeb.emit', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.NamedTemporaryFile', return_value=fp)
        with open(f'{pathlib.Path(__file__).parent}/output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(link_msg)
            mock_emit.assert_any_call(selector=output_selector, data=output_data)
