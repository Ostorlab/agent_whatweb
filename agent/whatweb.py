"""WhatWeb Agent : Agent responsible for finger-printing a website."""
import logging
import json
import subprocess
import tempfile
import os
from typing import Union
from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions

from agent import definitions as whatweb_definitions

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)

BLACKLISTED_PLUGINS = ['X-Frame-Options', 'RedirectLocation',
                       'Cookies', 'Access-Control-Allow-Methods', 'Content-Security-Policy',
                       'X-Forwarded-For', 'Via-Proxy', 'Allow', 'Strict-Transport-Security',
                       'X-XSS-Protection', 'x-pingback', 'Strict-Transport-Security',
                       'UncommonHeaders', 'HTML5', 'Script', 'Title', 'Email', 'Meta-Author',
                       'Frame', 'PasswordField', 'MetaGenerator', 'Object']
FINGERPRINT_TYPE = {
    'jquery': whatweb_definitions.FingerprintType.JAVASCRIPT_LIBRARY
}

WHATWEB_PATH = './whatweb'
WHATWEB_DIRECTORY = '/WhatWeb'
SELECTOR = 'v3.fingerprint.domain_name.library'

class WhatWebAgent(agent.Agent):
    """Agent responsible for finger-printing a website."""

    def _start_scan(self, target: whatweb_definitions.Target, output_file: Union[str, bytes, os.PathLike]):
        """Run a whatweb scan using python subprocess.

        Args:
            target:  Target
            output_file: The output file to save the scan result.
        """
        logger.info('Staring a new scan for %s .', target.domain_name)

        whatweb_command = [WHATWEB_PATH,
                           f'--log-json-verbose={output_file}',
                           target.domain_name
                           ]
        subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, cwd=WHATWEB_DIRECTORY)


    def _parse_result(self, target: whatweb_definitions.Target, output_file: Union[str, bytes, os.PathLike]):
        """After the scan is done, parse the output json file into a dict of the scan findings."""
        try:
            # whatweb writes duplicate lines in some cases, breaking json. We process only the first line.
            file_content = output_file.readlines()
            if file_content is not None and len(file_content) > 0:
                results = json.loads(file_content[0])
                for result in results:
                    if isinstance(result, list):
                        for list_plugin in result:
                            if len(list_plugin) > 0:
                                plugin = list_plugin[0]
                            else:
                                plugin = list_plugin
                            if plugin not in BLACKLISTED_PLUGINS:
                                values = list_plugin[1]
                                versions = ''
                                name = plugin
                                for value in values:
                                    if 'version' in value:
                                        versions = value['version']
                                    if 'string' in value:
                                        name = str(value['string'])
                                self._send_detected_fingerprints(
                                    target.domain_name, name, versions)
                logger.info('Scan is done Parsing the results from %s.', output_file.name)
        except OSError as e:
            logger.error('Exception while processing %s with message %s', output_file, e)

    def _send_detected_fingerprints(self, domain_name: str, name: str, versions: Union[list, str]):
        """Emits the identified fingerprints.

        Args:
            domain_name: The domain name.
            name: The name of the website.
            versions: The versions identified by WhatWeb Agent
        """

        fingerprint_type = FINGERPRINT_TYPE[name.lower()] if name.lower(
        ) in FINGERPRINT_TYPE else whatweb_definitions.FingerprintType.BACKEND_COMPONENT
        if isinstance(versions, list):
            for version in versions:
                msg_data = {
                    'domain_name': domain_name,
                    'library_name': name,
                    'library_version': str(version),
                    'library_type': fingerprint_type.name
                }
            self.emit(selector=SELECTOR, data=msg_data)
        else:
            msg_data = {
                'domain_name': domain_name,
                'library_name': name,
                'library_version': str(versions),
                'library_type': fingerprint_type.name
            }
            self.emit(selector=SELECTOR, data=msg_data)

    def _scan(self, target: whatweb_definitions.Target):
        """Start a scan, wait for the scan results and clean the scan output.

           returns:
            - Scan results from whatweb.
        """
        with tempfile.TemporaryFile() as fp:
            self._start_scan(target, fp.name)
            fp.seek(0)
            self._parse_result(target, fp)

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info('processing message of selector : %s', message.selector)
        target = whatweb_definitions.Target(
            domain_name=message.data['name'])
        self._scan(target=target)


if __name__ == '__main__':
    logger.info('WhatWeb agent starting ...')
    WhatWebAgent.main()
