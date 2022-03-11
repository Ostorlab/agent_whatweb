"""WhatWeb Agent: Agent responsible for finger-printing a website."""
import logging
import json
import subprocess
import tempfile
import io

from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True),],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

BLACKLISTED_PLUGINS = ['X-Frame-Options', 'RedirectLocation',
                       'Cookies', 'Access-Control-Allow-Methods', 'Content-Security-Policy',
                       'X-Forwarded-For', 'Via-Proxy', 'Allow', 'Strict-Transport-Security',
                       'X-XSS-Protection', 'x-pingback', 'Strict-Transport-Security',
                       'UncommonHeaders', 'HTML5', 'Script', 'Title', 'Email', 'Meta-Author',
                       'Frame', 'PasswordField', 'MetaGenerator', 'Object', 'Country', 'IP']

DEFAULT_FINGERPRINT = 'BACKEND_COMPONENT'

FINGERPRINT_TYPE = {
    'jquery': 'JAVASCRIPT_LIBRARY'
}

WHATWEB_PATH = './whatweb'
WHATWEB_DIRECTORY = '/WhatWeb'
SELECTOR = 'v3.fingerprint.domain_name.library'


class AgentWhatWeb(agent.Agent):
    """Agent responsible for finger-printing a website."""

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info('processing message of selector : %s', message.selector)
        with tempfile.TemporaryFile() as fp:
            self._start_scan(message.data['name'], fp.name)
            fp.seek(0)
            self._parse_emit_result(message.data['name'], fp)

    def _start_scan(self, domain_name: str, output_file: io.BytesIO):
        """Run a whatweb scan using python subprocess.

        Args:
            target:  Target
            output_file: The output file to save the scan result.
        """
        logger.info('Staring a new scan for %s .', domain_name)
        whatweb_command = [WHATWEB_PATH, f'--log-json-verbose={output_file}', domain_name]
        subprocess.run(whatweb_command, cwd=WHATWEB_DIRECTORY, check=True)

    def _parse_emit_result(self, domain_name: str, output_file: io.BytesIO):
        """After the scan is done, parse the output json file into a dict of the scan findings."""
        try:
            # whatweb writes duplicate lines in some cases, breaking json. We process only the first line.
            file_contents = output_file.readlines()
            if file_contents is not None and len(file_contents) > 0:
                for file_content in file_contents:
                    results = json.loads(file_content)
                    for result in results:
                        if isinstance(result, list):
                            for list_plugin in result:
                                if len(list_plugin) > 0:
                                    plugin = list_plugin[0]
                                else:
                                    plugin = list_plugin
                                if plugin not in BLACKLISTED_PLUGINS:
                                    values = list_plugin[1]
                                    versions = []
                                    name = plugin
                                    for value in values:
                                        if 'version' in value:
                                            if isinstance(value['version'], list):
                                                versions.extend(value['version'])
                                            else:
                                                versions.append(value['version'])
                                        if 'string' in value:
                                            name = str(value['string'])
                                    self._send_detected_fingerprints(domain_name, name, versions)
                logger.info('Scan is done Parsing the results from %s.', output_file.name)
        except OSError as e:
            logger.error('Exception while processing %s with message %s', output_file, e)

    def _send_detected_fingerprints(self, domain_name: str, name: str, versions: list):
        """Emits the identified fingerprints.

        Args:
            domain_name: The domain name.
            name: The name of the website.
            versions: The versions identified by WhatWeb Agent
        """

        fingerprint_type = FINGERPRINT_TYPE[name.lower()] if name.lower() in FINGERPRINT_TYPE else DEFAULT_FINGERPRINT
        if len(versions) > 0:
            for version in versions:
                msg_data = {
                    'domain_name': domain_name,
                    'library_name': name,
                    'library_version': str(version),
                    'library_type': fingerprint_type
                }
            self.emit(selector=SELECTOR, data=msg_data)
        else:
            msg_data = {
                'domain_name': domain_name,
                'library_name': name,
                'library_version': '',
                'library_type': fingerprint_type
            }
            self.emit(selector=SELECTOR, data=msg_data)


if __name__ == '__main__':
    logger.info('WhatWeb agent starting ...')
    AgentWhatWeb.main()