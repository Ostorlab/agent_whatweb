"""Pytest fixture for the whatweb agent."""
import pytest
import json

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions
from ostorlab.agent import message as m

from agent import whatweb_agent


@pytest.fixture
def domain_msg():
    """Creates a dummy message of type v3.asset.domain_name for testing purposes."""
    input_selector = 'v3.asset.domain_name'
    input_data = {'name': 'ostorlab.co'}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def link_msg():
    """Creates a dummy message of type v3.asset.link for testing purposes."""
    input_selector = 'v3.asset.link'
    input_data = {'url': 'http://ostorlab.co', 'method': 'GET'}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def whatweb_test_agent():
    """Creates a dummy agent for the WhatWeb Agent.
    """
    agent_definition = agent_definitions.AgentDefinition(name='whatweb')
    agent_settings = runtime_definitions.AgentSettings(
        key='whatweb',
        args=[
            defintions.Arg(name='schema',
                           type='string',
                           value=json.dumps('https').encode()),
            defintions.Arg(name='port',
                           type='number',
                           value=json.dumps(443).encode())
        ])
    return whatweb_agent.AgentWhatWeb(agent_definition, agent_settings)
