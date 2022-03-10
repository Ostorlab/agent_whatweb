"""Unittests for whatweb agent."""

import pytest
import tempfile

from ostorlab.agent import message as msg


def testWhatWebAgent_allChecks_emitsFingerprints(whatweb_test_agent):

    # selector = 'v3.fingerprint.domain_name.library'
    selector = 'v3.report.vulnerability'
    msg_data = {
        'domain_name': 'ostorlab.co',
        'library_name': 'Flutter',
        'library_version': '1.0.0',
        'library_type': 'Frontend'
    }
    message = msg.Message.from_data(selector=selector, data=msg_data)

    whatweb_test_agent.process(message)
    added_fingerprints = whatweb_test_agent._fingerprints_queue
    assert len(added_fingerprints) > 0
