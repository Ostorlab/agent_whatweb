"""WhatWeb MCP Server - Exposes WhatWeb fingerprinting as MCP tools."""

import logging
import subprocess

import fastmcp
import pydantic

from agent import definitions
from agent import whatweb_utils

logger = logging.getLogger(__name__)

mcp = fastmcp.FastMCP("WhatWeb Fingerprinting Server")


class Fingerprint(pydantic.BaseModel):
    """Represents a detected technology fingerprint."""

    name: str = pydantic.Field(..., description="The name of the detected technology.")
    version: str | None = pydantic.Field(
        None, description="The version of the detected technology, if available."
    )
    type: str = pydantic.Field(
        ...,
        description="The type of technology (e.g., BACKEND_COMPONENT, JAVASCRIPT_LIBRARY).",
    )


class ScanResult(pydantic.BaseModel):
    """Represents the result of a WhatWeb scan."""

    target_url: str = pydantic.Field(
        ..., description="The target URL that was scanned."
    )
    fingerprints: list[Fingerprint] = pydantic.Field(
        [], description="List of detected technology fingerprints."
    )


@mcp.tool()
def whatweb_scan(
    target: str,
    port: int | None = None,
    scheme: str | None = None,
    plugins: str | None = None,
) -> ScanResult:
    """Scan a web target to identify technologies and fingerprints.

    Args:
        target: The target to scan (domain, URL, or IP address).
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
        unique_fingerprints: list[Fingerprint] = []

        for fp in fingerprint_dicts:
            fp_name = fp["name"]
            fp_type = fp["type"]
            if fp_name is None or fp_type is None:
                continue

            key = (fp_name, fp["version"], fp_type)
            if key not in seen_fingerprints:
                seen_fingerprints.add(key)
                unique_fingerprints.append(
                    Fingerprint(
                        name=fp_name,
                        version=fp["version"],
                        type=fp_type,
                    )
                )

        return ScanResult(target_url=target_url, fingerprints=unique_fingerprints)

    except subprocess.CalledProcessError as e:
        logger.error("WhatWeb scan failed for target %s: %s", target, e)
        return ScanResult(target_url=target, fingerprints=[])
    except ValueError as e:
        logger.error("Invalid target configuration: %s", e)
        raise


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)
