"""WhatWeb scan tool implementation."""

import logging
import subprocess

from agent import definitions
from agent import whatweb_utils
from agent.mcp_server import models
from agent.mcp_server import server as mcp_server


logger = logging.getLogger(__name__)

mcp = mcp_server.mcp


@mcp.tool()
def whatweb_scan(
    target: str,
    port: int | None = None,
    scheme: str | None = None,
    plugins: str | None = None,
) -> models.ScanResult:
    """Scan a web target to identify technologies and fingerprints.

    Args:
        target: The target to scan (domain, URL, or                             0x7a9bd9882720> (id:
                             134809788098336)
                    INFO     whatweb_scan imported in __init__.py:10
                             tools/__init__.py
                    INFO     Tools imported             server.py:22
                             successfully
                    INFO     Starting MCP server with   server.py:33
                             transport: streamable-http
                    INFO     Registered tools: [] IP address).
        port: Optional port number to use (defaults to 80 for http, 443 for https).
        scheme: Optional URL scheme (http or https). Defaults to https.
        plugins: Optional comma-separated list of plugins (e.g., "django,wordpress").

    Returns:
        Scan results containing detected technology fingerprints.
    """
    plugin_list = plugins.split(",") if plugins else None

    if scheme is None:
        scheme = "https"

    if port is None:
        port = definitions.SCHEME_TO_PORT.get(scheme, 443)

    try:
        target_url = whatweb_utils.normalize_target(target, port, scheme)
        output_bytes = whatweb_utils.run_whatweb_scan(target_url, plugin_list)
        fingerprint_dicts = whatweb_utils.parse_whatweb_output(output_bytes)

        seen_fingerprints: set[tuple[str, str | None, str]] = set()
        unique_fingerprints: list[models.Fingerprint] = []

        for fp in fingerprint_dicts:
            fp_name = fp["name"]
            fp_type = fp["type"]
            if fp_name is None or fp_type is None:
                continue

            key = (fp_name, fp["version"], fp_type)
            if key not in seen_fingerprints:
                seen_fingerprints.add(key)
                unique_fingerprints.append(
                    models.Fingerprint(
                        name=fp_name,
                        version=fp["version"],
                        type=fp_type,
                    )
                )

        return models.ScanResult(
            target_url=target_url, fingerprints=unique_fingerprints
        )

    except subprocess.CalledProcessError as e:
        logger.error("WhatWeb scan failed for target %s: %s", target, e)
        return models.ScanResult(target_url=target, fingerprints=[])
    except ValueError as e:
        logger.error("Invalid target configuration: %s", e)
        raise
