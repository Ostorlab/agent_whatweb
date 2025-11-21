"""WhatWeb MCP Server - Exposes WhatWeb fingerprinting as MCP tools."""

import logging

import fastmcp
from fastmcp.tools import Tool

from agent.mcp_server import tools

logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "whatweb-mcp"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 8000

mcp = fastmcp.FastMCP(MCP_SERVER_NAME)
mcp.add_tool(Tool.from_function(tools.fingerprint))


def run() -> None:
    """Start the MCP server."""
    mcp.run(transport="http", host=MCP_SERVER_HOST, port=MCP_SERVER_PORT)


if __name__ == "__main__":
    run()
