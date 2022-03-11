"""Unittests for whatweb agent."""

import tempfile

from ostorlab.agent import message as msg


def testWhatWebAgent_withAllChecksEnabled_emitsFingerprints(whatweb_test_agent, mocker):
    """Test the whatweb agent with a given target address. The tests mocks the call to WhatWeb binary
    and validates the parsing and sending the findings to the queue
    """

    input_selector = 'v3.asset.domain_name'
    input_data = {'name': 'ostorlab.co',}

    output_selector = 'v3.fingerprint.domain_name.library'
    output_data = {
        'domain_name': 'ostorlab.co',
        'library_name': 'Google-Analytics',
        'library_version': 'Universal',
        'library_type': 'BACKEND_COMPONENT'
    }

    message = msg.Message.from_data(selector=input_selector, data=input_data)
    mocker.patch('subprocess.run', return_value=None)
    mock_emit = mocker.patch('agent.whatweb_agent.AgentWhatWeb.emit', return_value=None)
    with tempfile.TemporaryFile() as fp:
        mocker.patch('tempfile.TemporaryFile', return_value=fp)
        with open('tests/output.json', 'rb') as op:
            fp.write(op.read())
            fp.seek(0)
            whatweb_test_agent.process(message)
            mock_emit.assert_called_with(selector=output_selector, data=output_data)

