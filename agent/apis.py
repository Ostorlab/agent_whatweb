"""Add fingerprint API."""

import requests
import logging
import enum
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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


def _make_call(api_reporting_engine_base_url: str, reporting_engine_token: str,
               query: str, variables: Optional[Dict] = None):
    """Sends an API request.
    Args:
        api_reporting_engine_base_url: API url
        reporting_engine_token: Token to authenticate the request
        query: Graphql query to execute
        variables: Graphql variables
    Returns:
        The response.
    """
    headers = {'Authorization': f'Token {reporting_engine_token}'}
    response: requests.Response = requests.post(
        url=api_reporting_engine_base_url,
        json={'query': query, 'variables': variables or {}},
        headers=headers)
    logger.debug('response %s: %s', response.status_code, response.content)
    print('Backend Response: ', response.json())
    return response.json()


def call_add_fingerprints(api_reporting_engine_base_url: str, reporting_engine_token: str,
                          scan_id: int, fingerprints: List[Fingerprint]):
    """Defines the query to mark a scan as stopped.
    Args:
        api_reporting_engine_base_url: API url
        reporting_engine_token: Token to authenticate the request
        scan_id: reference scan id
    Returns:
        The response.
    """
    query = """
         mutation newFingerprint($scanId: Int!, $fingerprints: [FingerprintInputType]) {
            addFingerprints(scanId: $scanId, fingerprints: $fingerprints) {
               fingerprints {
                  id
               }
            }
         }
        """

    variables = {
        'scanId': scan_id,
        'fingerprints': [{
            'type': v.type.name.lower(),
            'name': v.name,
            'version': v.version,
            'detail': v.detail,
            'detailFormat': v.detail_format,
            'dna': v.dna,
        } for v in fingerprints]
    }

    return _make_call(api_reporting_engine_base_url, reporting_engine_token, query, variables)
