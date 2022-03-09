"""Simple wrapper for whatweb scanner."""

import json
import logging
import subprocess
import tempfile
import hashlib
from dataclasses import dataclass
from agent import apis

logger = logging.getLogger(__name__)


@dataclass
class Target:
    """Data Class for whatweb target."""
    address: str


class WhatWeb:
    """WhatWeb wrapper to enable using whatweb scanner from ostorlab agent class."""
    _output_file = None

    def __enter__(self):
        self._output_file = tempfile.NamedTemporaryFile(
            suffix='.json', prefix='whatweb', dir='/tmp', )
        return self

    def _get_target_address(self, target: Target):
        """Select the address for whatweb CLI based on the target type.

        Args:
            target: Target.

        Returns:
            - address for whatweb CLI target.
        """
        return target.address

    def _start_scan(self, target, output_file: str):
        """Run a whatweb scan using python subprocess.

        Args:
            target:  Target
            output_file: name of the output.
        """
        logger.info('Staring a new scan for %s .', target.address)

        whatweb_command = ['./whatweb',
                           f'--log-json-verbose={output_file}',
                           self._get_target_address(target)
                           ]
        subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, cwd='/WhatWeb')
        # process.communicate()[0].decode('utf-8')

    def _parse_result(self, output_file, target):
        """After the scan is done, parse the output json file into a dict of the scan findings.
        returns:
            - scan results.
        """
        logger.info('Scan is done Parsing the results from %s.',
                    output_file.name)
        try:
            with open(output_file, 'rb') as f:
                # whatweb writes duplicate lines in some cases, breaking json. We process only the first line.
                file_content = f.readlines()
                if file_content:
                    results = json.loads(file_content[0])
                    for result in results:
                        if isinstance(result, list):
                            for list_plugin in result:
                                plugin = list_plugin[0]
                                values = list_plugin[1]
                                detail = f"Found `{plugin}` in `{self._get_target_address(target)}`"
                                versions = None
                                name = plugin
                                for value in values:
                                    if 'regexp' in value:
                                        detail = f"Found `{plugin}` in `{self._get_target_address(target)}`: `{value['regexp']}`"
                                    if 'version' in value:
                                        versions = value['version']
                                    if 'string' in value:
                                        name = str(value['string'])
                                self._send_detected_fingerprints(self._get_target_address(target), name, detail, versions)
        except Exception as e:
            self.error(
                f'Exception while processing {output_file} with message {e}')
        # whatweb_result = json.load(output_file)
        # return whatweb_result

    def _send_detected_fingerprints(self, hostname, name, detail, versions):
        if versions:
            self._send_detected_fingerprints_with_version(hostname, name, detail, versions)
        else:
            self._send_detected_fingerprints_without_version(hostname, name, detail)

    def _send_detected_fingerprints_with_version(self, hostname, name, detail, versions):
        if isinstance(versions, list):
            for version in versions:
                fingerprint = apis.Fingerprint(type=type, name=name,
                                          version=version,
                                          detail=detail,
                                          detail_format='markdown',
                                          dna=self._compute_string_dna(detail, name, type, version))
                self._add_fingerprint(fingerprint)
                # self.send_message(
                #     WhatWeb.selector('fingerprint', 'lib'),
                #     name=fingerprint.name,
                #     version=str(fingerprint.version),
                #     type=fingerprint.type.name
                # )
        else:
            fingerprint = apis.Fingerprint(type=type, name=name,
                                      version=str(versions),
                                      detail=detail,
                                      detail_format='markdown',
                                      dna=self._compute_string_dna(detail, name, type, versions))
            self._add_fingerprint(fingerprint)
            # self.send_message(
            #     WhatWeb.selector('fingerprint', 'lib'),
            #     name=fingerprint.name,
            #     version=str(fingerprint.version),
            #     type=fingerprint.type.name
            # )

    def _add_fingerprint(self, fingerprint):
        self._vulnerabilities_queue.append(fingerprint)
        if len(self._vulnerabilities_queue) > self._vulnerabilities_queue_max_size:
            self._flush_vulnerabilities()

    def scan(self, target: Target):
        """Start a scan, wait for the scan results and clean the scan output.

           returns:
            - Scan results from whatweb.
        """

        self._start_scan(target, self._output_file.name)
        findings = self._parse_result(self._output_file, target)
        return findings

    @staticmethod
    def selector(*tags):
        # v2 to differentiate agents using the new api from agents using the old api.
        # v2.a.b.c.# will search for all message with a routing key that starts with a.b.c
        return '.'.join(['v2', *tags, '#'])

    def _compute_string_dna(self, detail, plugin, type, version=None):
        h = hashlib.md5()
        # h.update(str(self.reference_scan_id).encode())
        h.update(str(type).encode())
        h.update(plugin.encode())
        h.update(detail.encode())
        if version:
            h.update(version.encode())
        return h.hexdigest()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._output_file.close()
        return self


# testing code: to be removed
# print('!')
# output_file = tempfile.NamedTemporaryFile(
#     suffix='.json', prefix='whatweb', dir='/tmp', )
# whatweb_command = ['./whatweb',
#                    f'--log-json-verbose={output_file}', 'google.com']
# process = subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
#                      stderr=subprocess.PIPE, cwd='/WhatWeb')
# out = process.communicate()
# print('out ', out[0].decode('utf-8'))
# print('done')


# syntax = "proto2"

# message lib {
#     required int32 scan_id = 1
#     required string name = 2
#     optional string version = 3
#     required string type = 4
# }
