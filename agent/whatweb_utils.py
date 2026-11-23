"""Shared utilities for WhatWeb scanning."""

import io
import json
import logging
import os
import subprocess
import tempfile

from agent import definitions

logger = logging.getLogger(__name__)


def run_whatweb_scan(target_url: str) -> bytes:
    """Run WhatWeb binary and return raw output.

    Args:
        target_url: The URL to scan

    Raises:
        subprocess.TimeoutExpired: WhatWeb did not finish within WHATWEB_SCAN_TIMEOUT_SECONDS.
    """
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        output_file = fp.name

    try:
        whatweb_command = [
            definitions.WHATWEB_PATH,
            f"--log-json-verbose={output_file}",
            target_url,
        ]

        try:
            subprocess.run(
                whatweb_command,
                cwd=definitions.WHATWEB_DIRECTORY,
                check=True,
                timeout=definitions.WHATWEB_SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            log_scan_timeout(target_url=target_url)
            raise

        with open(output_file, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def log_scan_timeout(target_url: str) -> None:
    """Log that WhatWeb ran out of time on a target.

    Args:
        target_url: The URL WhatWeb was scanning.
    """
    logger.error(
        definitions.WHATWEB_SCAN_TIMEOUT_MESSAGE,
        target_url,
        definitions.WHATWEB_SCAN_TIMEOUT_SECONDS,
    )


def parse_whatweb_output(output_bytes: bytes) -> list[dict[str, str | None]]:
    """Parse WhatWeb JSON output and extract fingerprints.

    Returns:
        List of dicts with keys: name (str), version (str | None), type (str)
    """
    fingerprints: list[dict[str, str | None]] = []
    output_file = io.BytesIO(output_bytes)
    output_file.seek(0)

    try:
        file_contents = output_file.readlines()
        if file_contents is None or len(file_contents) == 0:
            return fingerprints

        for file_content in file_contents:
            scan_result = json.loads(file_content)

            if not isinstance(scan_result, list) or len(scan_result) < 3:
                continue

            plugins = scan_result[2]

            for plugin_entry in plugins:
                if not isinstance(plugin_entry, list) or len(plugin_entry) < 2:
                    continue

                plugin_name = plugin_entry[0]
                plugin_data = plugin_entry[1]

                if not isinstance(plugin_name, str):
                    continue

                if plugin_name in definitions.BLACKLISTED_PLUGINS:
                    continue

                versions: list[str] = []
                library_name: str = plugin_name

                for metadata in plugin_data:
                    if "version" in metadata:
                        if isinstance(metadata["version"], list):
                            versions.extend(metadata["version"])
                        else:
                            versions.append(str(metadata["version"]))
                    if "string" in metadata:
                        library_name = str(metadata["string"])

                fingerprint_type = definitions.FINGERPRINT_TYPE_MAP.get(
                    library_name.lower(), definitions.DEFAULT_FINGERPRINT_TYPE
                )

                if len(versions) > 0:
                    for version in versions:
                        fingerprints.append(
                            {
                                "name": library_name,
                                "version": version,
                                "type": fingerprint_type,
                            }
                        )
                else:
                    fingerprints.append(
                        {
                            "name": library_name,
                            "version": None,
                            "type": fingerprint_type,
                        }
                    )
    except (OSError, json.JSONDecodeError) as e:
        logger.error("Exception while processing WhatWeb output: %s", e)

    return fingerprints
