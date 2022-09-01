"""Pytest fixture for the whatweb agent."""
import pytest
import json
import pathlib

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions
from ostorlab.agent.message import message as m

from agent import whatweb_agent


@pytest.fixture
def domain_msg():
    """Creates a dummy message of type v3.asset.domain_name for testing purposes."""
    input_selector = 'v3.asset.domain_name'
    input_data = {'name': 'ostorlab.co'}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def domain_msg_with_port_and_schema():
    """Creates a dummy message of type v3.asset.domain_name.service for testing purposes."""
    input_selector = 'v3.asset.domain_name.service'
    input_data = {'name': 'ostorlab.co', 'port': 80, 'schema': 'http'}
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
def ip_msg():
    """Creates a dummy message of type v3.asset.ip for testing purposes."""
    input_selector = 'v3.asset.ip'
    input_data = {'host': '192.168.0.76'}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ip_msg_with_port_and_schema():
    """Creates a dummy message of type v3.asset.ip.v4.port.service for testing purposes."""
    input_selector = 'v3.asset.ip.v4.port.service'
    input_data = {'host': '192.168.0.0', 'port': 80, 'protocol': 'http'}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ip_msg_with_port_schema_mask():
    """Creates a dummy message of type v3.asset.ip.v4.port.service for testing purposes."""
    input_selector = 'v3.asset.ip.v4.port.service'
    input_data = {'host': '192.168.0.0', 'port': 80, 'mask': '31', 'protocol': 'http'}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ip_msg_with_port_schema_mask_2():
    """Creates a dummy message of type v3.asset.ip.v4.port.service for testing purposes."""
    input_selector = 'v3.asset.ip.v4.port.service'
    input_data = {'host': '192.168.0.0', 'port': 80, 'mask': '32', 'protocol': 'http'}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture(scope='function')
def whatweb_test_agent(agent_persist_mock):
    """WhatWeb Agent fixture for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key='whatweb',
            redis_url='redis://redis',
            args=[
                defintions.Arg(name='schema',
                            type='string',
                            value=json.dumps('https').encode()),
                defintions.Arg(name='port',
                            type='number',
                            value=json.dumps(443).encode())
            ])
        return whatweb_agent.AgentWhatWeb(agent_definition, agent_settings)
