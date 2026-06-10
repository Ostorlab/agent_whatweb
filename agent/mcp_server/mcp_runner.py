"""WhatWeb MCP server runner."""

import logging
import subprocess

logger = logging.getLogger(__name__)


SERVER_PATH = "/app/agent/mcp_server/server.py"


class MCPRunner:
    def __init__(
        self,
        universe: str,
        service_name: str,
        agent_key: str,
        hostname: str,
        host_hostname: str,
        agent_version: str = "",
        logging_credentials: str = "",
    ) -> None:
        self._universe: str = universe
        self._service_name: str = service_name
        self._agent_key: str = agent_key
        self._hostname: str = hostname
        self._host_hostname: str = host_hostname
        self._agent_version: str = agent_version
        self._logging_credentials: str = logging_credentials

    def run(self) -> None:
        """Start the MCP server process."""
        logger.info("Starting MCP server.")
        command: list[str] = [
            "python3.14",
            SERVER_PATH,
            "--universe",
            self._universe,
            "--service-name",
            self._service_name,
            "--agent-key",
            self._agent_key,
            "--hostname",
            self._hostname,
            "--host-hostname",
            self._host_hostname,
            "--agent-version",
            self._agent_version,
            "--logging-credentials",
            self._logging_credentials,
        ]
        subprocess.Popen(command)
