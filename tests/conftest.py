"""Pytest fixture for the whatweb agent."""

import pytest
import json
import pathlib
from typing import Dict, Union
import random

from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions
from ostorlab.agent.message import message as m

from agent import whatweb_agent


@pytest.fixture
def domain_msg() -> m.Message:
    """Creates a dummy message of type v3.asset.domain_name for testing purposes."""
    input_selector = "v3.asset.domain_name"
    input_data = {"name": "ostorlab.co"}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def domain_msg_with_port_and_schema() -> m.Message:
    """Creates a dummy message of type v3.asset.domain_name.service for testing purposes."""
    input_selector = "v3.asset.domain_name.service"
    input_data = {"name": "ostorlab.co", "port": 80, "schema": "http"}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def link_msg() -> m.Message:
    """Creates a dummy message of type v3.asset.link for testing purposes."""
    input_selector = "v3.asset.link"
    input_data = {"url": "http://ostorlab.co", "method": "GET"}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ip_msg() -> m.Message:
    """Creates a dummy message of type v3.asset.ip for testing purposes."""
    input_selector = "v3.asset.ip"
    input_data = {"host": "192.168.0.76"}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ipv6_msg() -> m.Message:
    """Creates a dummy message of type v3.asset.ip for testing purposes."""
    input_selector = "v3.asset.ip.v6"
    input_data = {"host": "2a00:1450:4006:80c::2004", "version": 6}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ip_msg_with_port_and_schema() -> m.Message:
    """Creates a dummy message of type v3.asset.ip.v4.port.service for testing purposes."""
    input_selector = "v3.asset.ip.v4.port.service"
    input_data = {"host": "192.168.0.0", "port": 80, "protocol": "http"}
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ip_msg_with_port_schema_mask() -> m.Message:
    """Creates a dummy message of type v3.asset.ip.v4.port.service for testing purposes."""
    input_selector = "v3.asset.ip.v4.port.service"
    input_data = {
        "host": "192.168.0.0",
        "port": 80,
        "mask": "32",
        "protocol": "http",
        "version": 4,
    }
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture
def ip_tcp_message() -> m.Message:
    """Creates a dummy message of type v3.asset.ip.v4.port.service for testing purposes."""
    input_selector = "v3.asset.ip.v4.port.service"
    input_data = {
        "host": "192.168.0.0",
        "port": 80,
        "mask": "32",
        "protocol": "tcp",
        "version": 4,
    }
    message = m.Message.from_data(selector=input_selector, data=input_data)
    return message


@pytest.fixture(scope="function")
def whatweb_test_agent(
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
) -> whatweb_agent.AgentWhatWeb:
    """WhatWeb Agent fixture for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="whatweb",
            redis_url="redis://redis",
            args=[
                defintions.Arg(
                    name="schema", type="string", value=json.dumps("https").encode()
                ),
                defintions.Arg(
                    name="port", type="number", value=json.dumps(443).encode()
                ),
            ],
        )
        return whatweb_agent.AgentWhatWeb(agent_definition, agent_settings)


@pytest.fixture(scope="function")
def whatweb_agent_with_scope_arg(
    agent_persist_mock: Dict[Union[str, bytes], Union[str, bytes]],
) -> whatweb_agent.AgentWhatWeb:
    """WhatWeb Agent fixture for testing purposes."""
    del agent_persist_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="whatweb",
            redis_url="redis://redis",
            args=[
                defintions.Arg(
                    name="schema", type="string", value=json.dumps("https").encode()
                ),
                defintions.Arg(
                    name="port", type="number", value=json.dumps(443).encode()
                ),
                defintions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*ostorlab.co").encode(),
                ),
            ],
        )
        return whatweb_agent.AgentWhatWeb(agent_definition, agent_settings)


@pytest.fixture()
def test_agent() -> whatweb_agent.AgentWhatWeb:
    """WhatWeb Agent fixture for testing purposes."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        agent_definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        agent_settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/whatweb",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[],
            healthcheck_port=random.randint(4000, 5000),
        )
        return whatweb_agent.AgentWhatWeb(agent_definition, agent_settings)


@pytest.fixture()
def scan_message_ipv4_with_mask8() -> m.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "8", "version": 4}
    return m.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv4_with_mask16() -> m.Message:
    """Creates a message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {"host": "192.168.1.17", "mask": "16", "version": 4}
    return m.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask64() -> m.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "64",
        "version": 6,
    }
    return m.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv6_with_mask112() -> m.Message:
    """Creates a message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:db8:3333:4444:5555:6666:7777:8888",
        "mask": "112",
        "version": 6,
    }
    return m.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def scan_message_ipv_with_incorrect_version() -> m.Message:
    """Creates a message of type v3.asset.ip with an incorrect version."""
    selector = "v3.asset.ip"
    msg_data = {
        "host": "0.0.0.0",
        "mask": "32",
        "version": 5,
    }
    return m.Message.from_data(selector, data=msg_data)
