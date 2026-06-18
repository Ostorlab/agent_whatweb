"""WhatWeb MCP Server."""

import base64
import json
import logging
import os
import time

import click
import google.cloud.logging
from google.oauth2 import service_account
import fastmcp
from fastmcp import tools as fastmcp_tools
from rich import logging as rich_logging

from agent.mcp_server import tools


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        rich_logging.RichHandler(rich_tracebacks=True),
    ],
    level="INFO",
    force=True,
)


logger = logging.getLogger(__name__)

MCP_SERVER_NAME = "whatweb-mcp"
MCP_SERVER_HOST = "0.0.0.0"
MCP_SERVER_PORT = 50051


def _configure_cloud_logging(
    logging_credential: str,
    agent_key: str,
    version: str,
) -> None:
    """Set up the logging configuration.

    Args:
        logging_credential: Logging credential of gcp logging.
        agent_key: Agent key.
        version: agent version.

    Returns:
        None
    """
    if logging_credential == "":
        logger.warning("Cloud logging is not configured.")
        return

    info = json.loads(base64.b64decode(logging_credential.encode()).decode())
    credentials = service_account.Credentials.from_service_account_info(info)  # type: ignore[no-untyped-call]
    client = google.cloud.logging.Client(credentials=credentials)  # type: ignore[no-untyped-call]
    client.setup_logging(  # type: ignore[no-untyped-call]
        labels={
            "agent_key": agent_key,
            "agent_version": version,
            "universe": os.environ.get("UNIVERSE", "") or "",
            "service_name": os.environ.get("SERVICE_NAME", "") or "",
            "hostname": os.environ.get("HOSTNAME", "") or "",
            "host_hostname": os.environ.get("HOST_HOSTNAME", "") or "",
        }
    )
    # GCO logging initialization is lazy, we need to log inorder trigger the init.
    # By default, GCP logging uses background thread, so we sleep to give it a chance to finish initialization
    logger.info("Cloud logging is setup")
    time.sleep(1)


def _run() -> None:
    """Starts the MCP server."""
    mcp = fastmcp.FastMCP(MCP_SERVER_NAME)
    mcp.add_tool(fastmcp_tools.Tool.from_function(tools.fingerprint))
    logger.info("Starting MCP server on %s:%s", MCP_SERVER_HOST, MCP_SERVER_PORT)
    mcp.run(transport="http", host=MCP_SERVER_HOST, port=MCP_SERVER_PORT)


@click.command()
@click.option("--agent-key", default="")
@click.option("--agent-version", default="")
def main(
    agent_key: str,
    agent_version: str,
) -> None:
    """Run the MCP server."""

    logging_credentials = os.environ.get("GCP_LOGGING_CREDENTIAL")
    if logging_credentials is not None:
        _configure_cloud_logging(
            logging_credential=logging_credentials,
            agent_key=agent_key,
            version=agent_version,
        )
    logger.info("Running mcp server..")
    _run()


if __name__ == "__main__":
    main()
