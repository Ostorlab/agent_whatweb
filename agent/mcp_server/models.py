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
