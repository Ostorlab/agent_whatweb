"""WhatWeb MCP Server runner."""

import base64
import json
import logging
import os

import google.cloud.logging
from google.oauth2 import service_account
import fastmcp
from fastmcp import tools as fastmcp_tools

from agent.mcp_server import tools

logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "whatweb-mcp"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 50051


def _configure_cloud_logging() -> None:
    logging_credential: str = os.environ.get("LOGGING_CREDENTIALS", "")
    universe: str = os.environ.get("UNIVERSE", "")
    version: str = os.environ.get("AGENT_VERSION", "")

    if logging_credential == "":
        logger.warning("Cloud logging is not configured.")
        return

    info = json.loads(base64.b64decode(logging_credential.encode()).decode())
    credentials = service_account.Credentials.from_service_account_info(info)  # type: ignore[no-untyped-call]
    client = google.cloud.logging.Client(credentials=credentials)  # type: ignore[no-untyped-call]
    client.setup_logging(  # type: ignore[no-untyped-call]
        labels={
            "agent_key": "whatweb",
            "agent_version": version,
            "universe": universe,
        }
    )


def _run() -> None:
    """Starts the MCP server."""
    mcp = fastmcp.FastMCP(MCP_SERVER_NAME)
    mcp.add_tool(fastmcp_tools.Tool.from_function(tools.fingerprint))
    logger.info("Starting MCP server on %s:%s", MCP_SERVER_HOST, MCP_SERVER_PORT)
    mcp.run(transport="http", host=MCP_SERVER_HOST, port=MCP_SERVER_PORT)


if __name__ == "__main__":
    _configure_cloud_logging()
    logger.info("Running mcp server..")
    _run()
