"""WhatWeb MCP Server - Exposes WhatWeb fingerprinting as MCP tools."""

import logging
import multiprocessing

import fastmcp
from fastmcp import tools as fastmcp_tools

from agent.mcp_server import tools

logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "whatweb-mcp"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 50051


def _run() -> None:
    mcp = fastmcp.FastMCP(MCP_SERVER_NAME)
    mcp.add_tool(fastmcp_tools.Tool.from_function(tools.fingerprint))
    logger.info("Starting MCP server on %s:%s", MCP_SERVER_HOST, MCP_SERVER_PORT)
    mcp.run(transport="http", host=MCP_SERVER_HOST, port=MCP_SERVER_PORT)


def run() -> None:
    """Start the MCP server in a background process."""

    mcp_process = multiprocessing.Process(
        target=_run,
    )
    mcp_process.start()


if __name__ == "__main__":
    run()
