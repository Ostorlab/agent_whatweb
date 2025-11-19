"""Shared definitions and constants for WhatWeb agent and tools."""

WHATWEB_PATH = "/usr/bin/whatweb"
WHATWEB_DIRECTORY = "/usr/share/whatweb"

BLACKLISTED_PLUGINS = [
    "X-Frame-Options",
    "RedirectLocation",
    "Cookies",
    "Access-Control-Allow-Methods",
    "Content-Security-Policy",
    "X-Forwarded-For",
    "Via-Proxy",
    "Allow",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "x-pingback",
    "UncommonHeaders",
    "HTML5",
    "Script",
    "Title",
    "Email",
    "Meta-Author",
    "Frame",
    "PasswordField",
    "MetaGenerator",
    "Object",
    "Country",
    "IP",
]

DEFAULT_FINGERPRINT_TYPE = "BACKEND_COMPONENT"

FINGERPRINT_TYPE_MAP: dict[str, str] = {"jquery": "JAVASCRIPT_LIBRARY"}

SCHEME_TO_PORT: dict[str, int] = {"http": 80, "https": 443}

IPV4_CIDR_LIMIT = 16
IPV6_CIDR_LIMIT = 112

DOMAIN_NAME_LIB_SELECTOR = "v3.fingerprint.domain_name.service.library"
IP_V4_LIB_SELECTOR = "v3.fingerprint.ip.v4.service.library"
IP_V6_LIB_SELECTOR = "v3.fingerprint.ip.v6.service.library"
