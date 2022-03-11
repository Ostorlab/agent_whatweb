"""Data types used by the whatweb agent."""

from dataclasses import dataclass

@dataclass
class Target:
    """Data Class for whatweb target."""
    domain_name: str

