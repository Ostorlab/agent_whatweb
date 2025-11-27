"""WhatWeb MCP Server - Exposes WhatWeb fingerprinting as MCP tools."""

import logging
import subprocess
import sys

logger = logging.getLogger(__name__)


def run() -> None:
    """Start the MCP server in a background process."""
    logger.info("Starting MCP server.")
    run_server_path = "/code/agent/mcp_server/run_server.py"
    subprocess.Popen([sys.executable, run_server_path])
