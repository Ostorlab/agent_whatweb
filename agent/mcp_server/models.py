"""Pydantic models for WhatWeb MCP server."""

import pydantic


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
