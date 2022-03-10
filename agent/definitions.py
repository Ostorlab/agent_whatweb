import enum
from typing import Optional
from dataclasses import dataclass

@dataclass
class Target:
    """Data Class for whatweb target."""
    address: str


class FingerprintType(enum.Enum):
    PROGRAMMING_LANGUAGE = 1
    JAVA_LIBRARY = 2
    ELF_LIBRARY = 3
    IOS_FRAMEWORK = 4
    DOTNET_FRAMEWORK = 5
    FLUTTER_FRAMEWORK = 6
    JAVASCRIPT_LIBRARY = 7
    CORDOVA_FRAMEWORK = 8
    MACHO_LIBRARY = 9
    PE_LIBRARY = 10
    BACKEND_COMPONENT = 11


@dataclass
class Fingerprint:
    type: FingerprintType
    name: str
    version: Optional[str]
    detail: str
    detail_format: str
    dna: str
