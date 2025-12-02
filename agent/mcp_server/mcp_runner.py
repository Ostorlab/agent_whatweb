"""WhatWeb MCP server runner."""

import logging
import subprocess

logger = logging.getLogger(__name__)


SERVER_PATH = "/app/agent/mcp_server/server.py"


class MCPRunner:
    def __init__(
        self, universe: str, agent_version: str = "", logging_credentials: str = ""
    ) -> None:
        self._universe: str = universe
        self._agent_version: str = agent_version
        self._logging_credentials: str = logging_credentials

    def run(self) -> None:
        """Start the MCP server process."""
        logger.info("Starting MCP server.")
        command: list[str] = [
            "python3.11",
            SERVER_PATH,
            "--universe",
            self._universe,
            "--agent-version",
            self._agent_version,
            "--logging-credentials",
            self._logging_credentials,
        ]
        subprocess.Popen(command)
