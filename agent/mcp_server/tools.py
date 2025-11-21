"""WhatWeb MCP server tools."""

import logging

from agent import whatweb_utils
from agent.mcp_server import models

logger = logging.getLogger(__name__)


def fingerprint(target: str) -> list[models.Fingerprint]:
    """Scan a web target to identify technologies and fingerprints.

    Args:
        target: Must be a complete URL including scheme (http/https) and port.

    Returns:
        List of detected technology fingerprints.
    """
    output_bytes = whatweb_utils.run_whatweb_scan(target)
    fingerprint_dicts = whatweb_utils.parse_whatweb_output(output_bytes)

    seen_fingerprints: set[tuple[str, str | None, str]] = set()
    unique_fingerprints: list[models.Fingerprint] = []

    for fp in fingerprint_dicts:
        name = str(fp["name"])
        version = fp["version"]
        fp_type = str(fp["type"])
        key = (name, version, fp_type)
        if key not in seen_fingerprints:
            seen_fingerprints.add(key)
            unique_fingerprints.append(
                models.Fingerprint(name=name, version=version, type=fp_type)
            )

    return unique_fingerprints
