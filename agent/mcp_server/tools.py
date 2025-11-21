"""WhatWeb MCP server tools."""

import logging
import subprocess

from agent import whatweb_utils
from agent.mcp_server import models

logger = logging.getLogger(__name__)


def fingerprint(target: str) -> models.ScanResult:
    """Scan a web target to identify technologies and fingerprints.

    Args:
        target: Must be a complete URL including scheme (http/https) and port.

    Returns:
        Scan results containing detected technology fingerprints.
    """
    try:
        output_bytes = whatweb_utils.run_whatweb_scan(target)
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

        return models.ScanResult(target_url=target, fingerprints=unique_fingerprints)

    except subprocess.CalledProcessError as e:
        logger.error("WhatWeb scan failed for target %s: %s", target, e)
        return models.ScanResult(target_url=target, fingerprints=[])
    except ValueError as e:
        logger.error("Invalid target configuration: %s", e)
        raise
