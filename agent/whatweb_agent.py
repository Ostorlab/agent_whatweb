"""WhatWeb Agent : Agent responsible for identifying a website."""

import logging
import json
import subprocess
import tempfile
import hashlib
from dataclasses import dataclass
from rich import logging as rich_logging

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions

from agent import apis
from agent.whatweb import whatweb

@dataclass
class Target:
    """Data Class for whatweb target."""
    address: str

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)
logger.setLevel('DEBUG')


class WhatWebAgent(agent.Agent):
    """Agent responsible for identifying a website."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        """Inits the whatweb agent."""
        super().__init__(agent_definition, agent_settings)
        self._fingerprints_queue = []
        self._reporting_engine_token = self.args.get('reporting_engine_token')
        self._api_reporting_engine_base_url = self.args.get('api_reporting_engine_base_url')
        self._fingerprints_queue_max_size = int(self.args.get('fingerprints_queue_max_size'))
        self._reference_scan_id: int = int(self.args.get('reference_scan_id'))
        self._output_file = tempfile.NamedTemporaryFile(suffix='.json', prefix='whatweb', dir='/tmp', )

    def _start_scan(self, target, output_file: str):
        """Run a whatweb scan using python subprocess.

        Args:
            target:  Target
            output_file: name of the output.
        """
        logger.info('Staring a new scan for %s .',
                    self._get_target_address(target))

        whatweb_command = ['./whatweb',
                           f'--log-json-verbose={output_file}',
                           self._get_target_address(target)
                           ]
        process = subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd='/WhatWeb')
        process.communicate()[0].decode('utf-8')

    def _get_target_address(self, target: Target):
        """Select the address for whatweb CLI based on the target type.

        Args:
            target: Target.

        Returns:
            - address for whatweb CLI target.
        """
        return target.address

    def _parse_result(self, output_file, target: Target):
        """After the scan is done, parse the output json file into a dict of the scan findings.
        returns:
            - scan results.
        """
        try:
            with output_file as f:
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
                                self._send_detected_fingerprints(
                                    self._get_target_address(target), name, detail, versions)
                logger.info('Scan is done Parsing the results from %s.', output_file.name)
        except Exception as e:
            logger.error(
                f'Exception while processing {output_file} with message {e}')
        # whatweb_result = json.load(output_file)
        # return whatweb_result

    def _send_detected_fingerprints(self, hostname, name, detail, versions):
        if versions:
            self._send_detected_fingerprints_with_version(
                hostname, name, detail, versions)
        else:
            self._send_detected_fingerprints_without_version(
                hostname, name, detail)

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
            #     WhatWebAgent.selector('fingerprint', 'lib'),
            #     name=fingerprint.name,
            #     version=str(fingerprint.version),
            #     type=fingerprint.type.name
            # )

    def _send_detected_fingerprints_without_version(self, hostname, name, detail):
        fingerprint = apis.Fingerprint(type=type, name=name,
                                  version=None,
                                  detail=detail,
                                  detail_format='markdown',
                                  dna=self._compute_string_dna(detail, name, type))

        self._add_fingerprint(fingerprint)
        # self.send_message(
        #     WhatWebAgent.selector('fingerprint', 'lib'),
        #     name=fingerprint.name,
        #     version=str(fingerprint.version),
        #     type=fingerprint.type.name
        # )

    def _add_fingerprint(self, fingerprint: apis.Fingerprint):
        self._fingerprints_queue.append(fingerprint)
        if len(self._fingerprints_queue) > self._fingerprints_queue_max_size:
            self._flush_fingerprints()

    def _flush_fingerprints(self):
        if self._fingerprints_queue:
            apis.call_add_fingerprints(self._api_reporting_engine_base_url, self._reporting_engine_token,
                                       self._reference_scan_id, self._fingerprints_queue)
            self._fingerprints_queue = []

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

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        data = {
            'url': 'ostorlab.co'
        }
        target = whatweb.Target(address=data['url'])
        self.scan(target=target)
        logger.info('Scan finished Number of findings')

        del message
        logger.info('processing message')

    def __exit__(self):
        self._output_file.close()
        return self

# if __name__ == '__main__':
#     logger.info('WhatWeb agent starting ...')
#     WhatWebAgent.main()


# testing code: to be removed
if __name__ == '__main__':
    token = {
                'name': 'reporting_engine_token',
                'type': 'string',
                'value': '9659f19efc5613429c99c960c2f4e8f498b56ab0'
            }
    url = {
        'name': 'api_reporting_engine_base_url',
        'type': 'string',
        'value': 'https://api.ostorlab.co/apis/robot_graphql'
    }
    max_size = {
        'name': 'fingerprints_queue_max_size',
        'type': 'number',
        'value': 10
    }
    scan_id = {
        'name': 'reference_scan_id',
        'type': 'number',
        'value': 52063
    }

    agent_definition = agent_definitions.AgentDefinition(
        name='whatweb',
        args=[token, url, max_size, scan_id]
    )
    agent_settings = runtime_definitions.AgentSettings(
        key='whatweb'
    )
    whatWeb = WhatWebAgent(agent_definition, agent_settings)
    data = {
        'url': 'ostorlab.co'
    }

    target = Target(address=data['url'])
    whatWeb.scan(target=target)

    # print('!')
    # output_file = tempfile.NamedTemporaryFile(
    #     suffix='.json', prefix='whatweb', dir='/tmp', )
    # whatweb_command = ['./whatweb',
    #                 f'--log-json-verbose={output_file}', 'google.com']
    # process = subprocess.Popen(whatweb_command, stdout=subprocess.PIPE,
    #                     stderr=subprocess.PIPE, cwd='/WhatWeb')
    # out = process.communicate()
    # print('out ', out[0].decode('utf-8'))
    # print('done')
