"""WhatWeb MCP Server runner."""

import logging

import fastmcp
from fastmcp import tools as fastmcp_tools

from agent.mcp_server import tools

logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "whatweb-mcp"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 50051


def main() -> None:
    """Starts the MCP server."""
    logging.basicConfig(level=logging.INFO)
    mcp = fastmcp.FastMCP(MCP_SERVER_NAME)
    mcp.add_tool(fastmcp_tools.Tool.from_function(tools.fingerprint))
    logger.info("Starting MCP server on %s:%s", MCP_SERVER_HOST, MCP_SERVER_PORT)
    mcp.run(transport="http", host=MCP_SERVER_HOST, port=MCP_SERVER_PORT)


if __name__ == "__main__":
    main()
