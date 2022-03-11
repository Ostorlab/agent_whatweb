"""Pytest fixture for the whatweb agent."""
import pytest

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from agent import whatweb


@pytest.fixture
def whatweb_test_agent():
    """Creates a dummy agent for the WhatWeb Agent.
    """
    agent_definition = agent_definitions.AgentDefinition(name='whatweb')
    agent_settings = runtime_definitions.AgentSettings(key='whatweb')
    return whatweb.WhatWebAgent(agent_definition, agent_settings)
