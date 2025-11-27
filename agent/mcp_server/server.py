"""WhatWeb MCP Server - Exposes WhatWeb fingerprinting as MCP tools."""

import logging
import subprocess

logger = logging.getLogger(__name__)


def run() -> None:
    """Start the MCP server in a background process."""
    logger.info("Starting MCP server.")
    run_server_path = "/app/agent/mcp_server/run_server.py"
    subprocess.Popen(["python3.11", run_server_path])
