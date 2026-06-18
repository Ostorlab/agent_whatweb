"""WhatWeb MCP server runner."""

import logging
import subprocess

logger = logging.getLogger(__name__)


SERVER_PATH = "/app/agent/mcp_server/server.py"


class MCPRunner:
    def __init__(
        self,
        agent_key: str,
        agent_version: str = "",
    ) -> None:
        self._agent_key: str = agent_key
        self._agent_version: str = agent_version

    def run(self) -> None:
        """Start the MCP server process."""
        logger.info("Starting MCP server.")
        command: list[str] = [
            "python3.14",
            SERVER_PATH,
            "--agent-key",
            self._agent_key,
            "--agent-version",
            self._agent_version,
        ]
        subprocess.Popen(command)
