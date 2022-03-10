"""Pytest fixture for the whatweb agent."""
import pytest

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from agent import whatweb


@pytest.fixture
def whatweb_test_agent():
    """Creates a dummy agent for the WhatWeb Agent.
    """
    max_size = {
        'name': 'fingerprints_queue_max_size',
        'type': 'number',
        'value': 2
    }
    reference_scan_id = {
        'name': 'reference_scan_id',
        'type': 'number',
        'value': 1
    }

    agent_definition = agent_definitions.AgentDefinition(
        name='whatweb',
        args=[max_size, reference_scan_id]
    )
    agent_settings = runtime_definitions.AgentSettings(
        key='whatweb'
    )
    return whatweb.WhatWebAgent(agent_definition, agent_settings)
