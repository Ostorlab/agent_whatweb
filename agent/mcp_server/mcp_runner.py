"""WhatWeb MCP Server - Exposes WhatWeb fingerprinting as MCP tools."""

import logging
import subprocess

logger = logging.getLogger(__name__)


SERVER_PATH = "/app/agent/mcp_server/run_server.py"


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
        command = self._prepare_command()
        subprocess.Popen(command)

    def _prepare_command(self) -> list[str]:
        command: list[str] = [
            "python3.11",
            SERVER_PATH,
            self._agent_version,
            self._universe,
            self._logging_credentials,
        ]
        return command
