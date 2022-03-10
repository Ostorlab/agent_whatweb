"""WhatWeb Agent : Agent responsible for finger-printing a website."""

from dbm.ndbm import library
import logging
import json
import subprocess
import tempfile
import hashlib
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

class WhatWebAgent(agent.Agent):
    """Agent responsible for identifying a website."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        """Inits the whatweb agent."""
        super().__init__(agent_definition, agent_settings)
        # self._selector = 'v3.fingerprint.domain_name.library'
        self._selector = 'v3.report.vulnerability' # to replace after ostorlab new relase is made
        self._fingerprints_queue = []
        self._fingerprints_queue_max_size = int(
            self.args.get('fingerprints_queue_max_size'))
        self._reference_scan_id: int = int(self.args.get('reference_scan_id'))
        self._output_file = tempfile.NamedTemporaryFile(
            suffix='.json', prefix='whatweb', dir='/tmp', )

    def _start_scan(self, target, output_file: str):
        """Run a whatweb scan using python subprocess.

        Args:
            target:  Target
            output_file: name of the output.
        """
        logger.info('Staring a new scan for %s .', target.domain_name)

        whatweb_command = [WHATWEB_PATH,
                           f'--log-json-verbose={output_file}',
                           target.domain_name
                           ]
        process = subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=WHATWEB_DIRECTORY)
        process.communicate()[0].decode('utf-8')

    def _parse_result(self, target: whatweb_definitions.Target, output_file):
        """After the scan is done, parse the output json file into a dict of the scan findings."""
        try:
            with output_file as f:
                # whatweb writes duplicate lines in some cases, breaking json. We process only the first line.
                file_content = f.readlines()
                if file_content is not None and len > 0:
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
                                    detail = f"Found `{plugin}` in `{target.domain_name}`"
                                    versions = None
                                    name = plugin
                                    for value in values:
                                        if 'regexp' in value:
                                            detail = f"Found `{plugin}` in `{target.domain_name}`: `{value['regexp']}`"
                                        if 'version' in value:
                                            versions = value['version']
                                        if 'string' in value:
                                            name = str(value['string'])
                                    self._send_detected_fingerprints(target.domain_name, name, detail, versions)
                logger.info(
                    'Scan is done Parsing the results from %s.', output_file.name)
        except Exception as e:
            logger.error(
                f'Exception while processing {output_file} with message {e}')

    def _send_detected_fingerprints(self, domain_name: str, name: str, detail: str, versions: str):
        """Emits the identified fingerprints.

        Args:
            domain_name: The domain name.
            name: The name of the website.
            detail: Fingerprint detail.
            versions: The versions identified by WhatWeb Agent
        """
        if versions:
            self._send_detected_fingerprints_with_version(
                domain_name, name, detail, versions)
        else:
            self._send_detected_fingerprints_without_version(
                domain_name, name, detail)

    def _send_detected_fingerprints_with_version(self, domain_name: str, name: str, detail: str, versions: str):
        """Emits the identified fingerprints.

        Args:
            domain_name: The domain name.
            name: The name of the website.
            detail: Fingerprint detail.
            versions: The versions identified by WhatWeb Agent
        """
        type = FINGERPRINT_TYPE[name.lower()] if name.lower(
        ) in FINGERPRINT_TYPE else whatweb_definitions.FingerprintType.BACKEND_COMPONENT
        if isinstance(versions, list):
            for version in versions:
                fingerprint = whatweb_definitions.Fingerprint(type=type, name=name,
                                               version=version,
                                               detail=detail,
                                               detail_format='markdown',
                                               dna=self._compute_string_dna(detail, name, type, version))
                msg_data = {
                    'domain_name': domain_name,
                    'library_name': fingerprint.name,
                    'library_version': str(fingerprint.version),
                    'library_type': fingerprint.type.name
                }

            self._add_fingerprint(fingerprint)
            self.emit(selector=self._selector, data=msg_data)
        else:
            fingerprint = whatweb_definitions.Fingerprint(type=type, name=name,
                                           version=str(versions),
                                           detail=detail,
                                           detail_format='markdown',
                                           dna=self._compute_string_dna(detail, name, type, versions))
            msg_data = {
                'domain_name': domain_name,
                'library_name': fingerprint.name,
                'library_version': str(fingerprint.version),
                'library_type': fingerprint.type.name
            }

            self._add_fingerprint(fingerprint)
            self.emit(selector=self._selector, data=msg_data)

    def _send_detected_fingerprints_without_version(self, domain_name, name, detail):
        """Emits the identified fingerprints without the version(s).

        Args:
            domain_name: The domain name.
            name: The name of the website.
            detail: Fingerprint detail.
        """
        type = FINGERPRINT_TYPE[name.lower()] if name.lower(
        ) in FINGERPRINT_TYPE else whatweb_definitions.FingerprintType.BACKEND_COMPONENT
        fingerprint = whatweb_definitions.Fingerprint(type=type, name=name,
                                       version=None,
                                       detail=detail,
                                       detail_format='markdown',
                                       dna=self._compute_string_dna(detail, name, type))
        msg_data = {
            'domain_name': domain_name,
            'library_name': fingerprint.name,
            'library_version': None,
            'library_type': fingerprint.type.name
        }

        self._add_fingerprint(fingerprint)
        self.emit(selector=self._selector, data=msg_data)

    def _add_fingerprint(self, fingerprint: whatweb_definitions.Fingerprint):
        """Add a fingerprint to the queue.

        Args:
            fingerprint (whatweb_definitions.Fingerprint): The fingerprint to add to the queue.
        """
        self._fingerprints_queue.append(fingerprint)
        if len(self._fingerprints_queue) > self._fingerprints_queue_max_size:
            self._flush_fingerprints()

    def _flush_fingerprints(self):
        """Empties the queue containing fingerprints."""
        self._fingerprints_queue = []

    def _scan(self, target: whatweb_definitions.Target):
        """Start a scan, wait for the scan results and clean the scan output.

           returns:
            - Scan results from whatweb.
        """
        self._start_scan(target, self._output_file)
        findings = self._parse_result(self._output_file, target)
        return findings

    @staticmethod
    def selector(*tags):
        # v3 to differentiate agents using the new api from agents using the old api.
        # v3.a.b.c.# will search for all message with a routing key that starts with a.b.c
        return '.'.join(['v3', *tags, '#'])

    def _compute_string_dna(self, detail, plugin, type, version=None):
        """Computes the DNA of the fingerprint

        Args:
            detail: The detail of the identified fingerprint.
            plugin: The plugin identified by WhatWeb.
            type: The type of plugin identified by WhatWeb.
            version: The version of the target domain.
        """
        h = hashlib.md5()
        h.update(str(self._reference_scan_id).encode())
        h.update(str(type).encode())
        h.update(plugin.encode())
        h.update(detail.encode())
        if version:
            h.update(version.encode())
        return h.hexdigest()

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info('processing message of selector : %s', message.selector)
        target = whatweb_definitions.Target(domain_name=message.data['domain_name'])
        self._scan(target=target)

if __name__ == '__main__':
    logger.info('WhatWeb agent starting ...')
    WhatWebAgent.main()
