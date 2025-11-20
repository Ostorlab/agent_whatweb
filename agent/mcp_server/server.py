"""WhatWeb MCP Server - Exposes WhatWeb fingerprinting as MCP tools."""

import logging

from mcp.server import fastmcp


logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "whatweb-mcp"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 8000

mcp: fastmcp.FastMCP = fastmcp.FastMCP(
    name=MCP_SERVER_NAME, host=MCP_SERVER_HOST, port=MCP_SERVER_PORT
)


def run() -> None:
    """Start the MCP server with the streamable-http transport."""
    mcp.run(transport="streamable-http")


def main() -> None:
    """Entry point for the WhatWeb MCP server."""
    run()


if __name__ == "__main__":
    main()
