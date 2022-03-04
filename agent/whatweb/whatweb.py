# """Simple wrapper for whatweb scanner."""
# import json
# import logging
# import subprocess
# import tempfile
# from dataclasses import dataclass

# logger = logging.getLogger(__name__)


# @dataclass
# class Target:
#     """Data Class for whatweb target."""
#     address: str


# class WhatWeb:
#     """WhatWeb wrapper to enable using whatweb scanner from ostorlab agent class."""
#     _output_file = None

#     def __enter__(self):
#         self._output_file = tempfile.NamedTemporaryFile(
#             suffix='.json', prefix='whatweb', dir='/tmp', )
#         return self

#     def _get_target_arg(self, target: Target):
#         """Select the right argument for whatweb CLI based on the target type.

#         Args:
#             target: Target.

#         Returns:
#             - argument for whatweb CLi target.

#         Raises:
#             - ValueError: the provided  ip version is incorrect.
#         """
#         target.address

#     def _start_scan(self, target, output_file: str):
#         """Run a whatweb scan using python subprocess.

#         Args:
#             target:  Target
#             output_file: name of the output.
#         """
#         logger.info('Staring a new scan for %s .', target.address)
#         grant_permission = ['cd', 'WhatWeb;', 'chmod +x whatweb']
#         subprocess.run(grant_permission, encoding='utf-8',
#                        stdout=subprocess.DEVNULL, check=True)

#         whatweb_command = ['cd', '/WhatWeb;', './whatweb',
#                            '--verbose',
#                            'google.com'
#                            ]

#         subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
#                          stderr=subprocess.PIPE)

#     def _parse_result(self, output_file):
#         """After the scan is done, parse the output json file into a dict of the scan findings.
#         returns:
#             - scan results.
#         """
#         logger.info('Scan is done Parsing the results from %s.',
#                     output_file.name)
#         whatweb_result = json.load(output_file)
#         return whatweb_result

#     def scan(self, target: Target):
#         """Start a scan, wait for the scan results and clean the scan output.

#            returns:
#             - Scan results from whatweb.
#         """
#         self._start_scan(target, self._output_file.name)
#         findings = self._parse_result(self._output_file)
#         return findings

#     def __exit__(self, exc_type, exc_val, exc_tb):
#         self._output_file.close()
#         return self

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass

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

    def _get_target_arg(self, target: Target):
        """Select the right argument for whatweb CLI based on the target type.

        Args:
            target: Target.

        Returns:
            - argument for whatweb CLi target.

        Raises:
            - ValueError: the provided  ip version is incorrect.
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
                           self._get_target_arg(target),
                           f'--log-json-verbose={output_file}'
                           ]
        subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, cwd='/WhatWeb')

    def _parse_result(self, output_file):
        """After the scan is done, parse the output json file into a dict of the scan findings.
        returns:
            - scan results.
        """
        logger.info('Scan is done Parsing the results from %s.',
                    output_file.name)
        whatweb_result = json.load(output_file)
        return whatweb_result

    def scan(self, target: Target):
        """Start a scan, wait for the scan results and clean the scan output.

           returns:
            - Scan results from whatweb.
        """

        self._start_scan(target, self._output_file.name)
        findings = self._parse_result(self._output_file)
        print('Findings ', findings)
        return findings

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._output_file.close()
        return self

# testing code: to be removed
print('!')
whatweb_command = ['./whatweb',
                   '--log-json-verbose=whatweb.json', 'google.com']
p = subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, cwd='/WhatWeb')
out= p.communicate()

print('out :', out)
print('done')
