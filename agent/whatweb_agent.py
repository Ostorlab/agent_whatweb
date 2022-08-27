"""WhatWeb Agent: Agent responsible for finger-printing a website."""
import io
import json
import logging
import subprocess
import ipaddress
import tempfile
from typing import List, Optional
from urllib import parse
import dataclasses

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent.kb import kb
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from rich import logging as rich_logging

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True), ],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

VULNZ_TITLE = 'Tech Stack Fingerprint'
VULNZ_ENTRY_RISK_RATING = 'INFO'
VULNZ_SHORT_DESCRIPTION = 'List of web technologies recognized'
VULNZ_DESCRIPTION = """Lists web technologies including content management systems(CMS), blogging platforms,
statistic/analytics packages, JavaScript libraries, web servers, embedded devices, version numbers, email addresses,
account IDs, web framework modules, SQL errors, and more."""

# These are verbose non-preferred plugins.
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
LIB_SELECTOR = 'v3.fingerprint.domain_name.service.library'
SCHEME_TO_PORT = {'http': 80, 'https': 443}


@dataclasses.dataclass
class Target:
    name: str
    schema: Optional[str] = None
    port: Optional[int] = None

class AgentWhatWeb(agent.Agent,
                   agent_report_vulnerability_mixin.AgentReportVulnMixin,
                   persist_mixin.AgentPersistMixin):
    """Agent responsible for finger-printing a website."""

    def __init__(self,
                 agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:

        agent.Agent.__init__(self, agent_definition, agent_settings)
        agent_report_vulnerability_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info('processing message of selector : %s', message.selector)
        targets = self._prepare_targets(message)
        for target in targets:
            if self._is_target_already_processed(message) is False:
                continue
            else:
                with tempfile.NamedTemporaryFile() as fp:
                    self._start_scan(target.name, fp.name)
                    self._parse_emit_result(
                        target.name, fp, int(target.port), target.schema)

    def _prepare_targets(self, message: msg.Message) -> List[Target]:
        """Returns a list of target objects to be scanned."""
        targets = []
        domain_targets = self._prepare_domain_targets(message)
        ip_targets = self._prepare_ip_targets(message)
        targets.extend(domain_targets)
        targets.extend(ip_targets)
        return targets

    def _get_port(self, message: msg.Message) -> int:
        """Returns the port to be used for the target."""
        if message.data.get('port') is not None:
            return message.data['port']
        else:
            return self.args.get('port')

    def _get_schema(self, message: msg.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get('schema') is not None:
            return message.data['schema']
        elif message.data.get('protocol') is not None:
            return message.data['protocol']
        else:
            return self.args.get('schema')

    def _prepare_domain_targets(self, message: msg.Message) -> List[Target]:
        """Returns a list of domain targets to be scanned."""
        targets = []
        if message.data.get('url') is not None:
            target = self._get_target_from_url(message.data['url'])
            targets.append(target)
        elif message.data.get('name') is not None:
            domain_name = message.data['name']
            target = Target(name=domain_name, schema=self._get_schema(message), port=self._get_port(message))
            targets.append(target)

        return targets

    def _prepare_ip_targets(self, message: msg.Message) -> List[Target]:
        """Returns a list of ip targets to be scanned."""
        targets = []
        host = message.data.get('host')
        mask = message.data.get('mask')

        if host is None:
            return targets

        if mask is not None:
            try:
                addresses = ipaddress.ip_network(f'{host}/{mask}')
                for address in addresses.hosts():
                    targets.append(Target(name=str(address),
                                          schema=self._get_schema(message), port=self._get_port(message)))
            except ValueError as e:
                logger.error('Invalid IP or mask. %s', e)
        else:
            try:
                addresses = ipaddress.ip_network(host)
                for address in addresses.hosts():
                    targets.append(Target(name=str(address),
                                          schema=self._get_schema(message), port=self._get_port(message)))
            except ValueError as e:
                logger.error('Invalid IP. %s', e)

        return targets

    def _is_target_already_processed(self, message) -> bool:
        """Checks if the target has already been processed before, relies on the redis server."""
        if message.data.get('url') is not None or message.data.get('name') is not None:
            if message.data.get('url') is not None:
                target = self._get_target_from_url(message.data['url'])
                unicity_check_key = f'{target.schema}_{target.name}_{target.port}'
            elif message.data.get('name') is not None:
                port = self._get_port(message)
                schema = self._get_schema(message)
                domain = message.data['name']
                unicity_check_key = f'{schema}_{domain}_{port}'

            if self.set_add(b'agent_whatweb_asset', unicity_check_key) is True:
                return True
            else:
                logger.info('target %s/ was processed before, exiting', unicity_check_key)
                return False
        elif message.data.get('host') is not None:
            host = message.data.get('host')
            mask = message.data.get('mask')
            if mask is not None:
                addresses = ipaddress.ip_network(f'{host}/{mask}')
                result = self.add_ip_network('agent_whois_ip_asset', addresses, lambda net: f'X_{net}_Y')
            else:
                addresses = host
                result = self.set_add('agent_whois_ip_asset', host)

            if result is False:
                logger.info('target %s was processed before, exiting', addresses)
            return result

    def _get_target_from_url(self, url: str) -> tuple:
        """Compute schema and port from an URL"""
        parsed_url = parse.urlparse(url)
        schema = parsed_url.scheme or self.args.get('schema')
        domain_name = parse.urlparse(url).netloc
        port = 0
        if len(parsed_url.netloc.split(':')) > 1:
            domain_name = parsed_url.netloc.split(':')[0]
            port = parsed_url.netloc.split(':')[-1]
        port = int(port) or SCHEME_TO_PORT.get(schema) or self.args.get('port')
        target = Target(name=domain_name, schema=schema, port=port)
        return target

    def _start_scan(self, name: str, output_file: str):
        """Run a whatweb scan using python subprocess.

        Args:
            name: Target domain name or ip address.
            output_file: The output file to save the scan result.
        """
        logger.info('Staring a new scan for %s .', name)
        whatweb_command = [WHATWEB_PATH,
                           f'--log-json-verbose={output_file}', name]
        subprocess.run(whatweb_command, cwd=WHATWEB_DIRECTORY, check=True)

    def _parse_emit_result(self, name: str, output_file: io.BytesIO,
                           port: Optional[int] = None, schema: Optional[str] = None):
        """After the scan is done, parse the output json file into a dict of the scan findings."""
        output_file.seek(0)
        try:
            # whatweb writes duplicate lines in some cases, breaking json. We process only the first line.
            file_contents = output_file.readlines()
            if file_contents is None or len(file_contents) == 0:
                return

            for file_content in file_contents:
                results = json.loads(file_content)
                for result in results:
                    if isinstance(result, list):
                        for list_plugin in result:
                            # Take first item only.
                            if len(list_plugin) > 0:
                                plugin = list_plugin[0]
                            else:
                                plugin = list_plugin

                            # Discard blacklisted plugins.
                            if plugin not in BLACKLISTED_PLUGINS:
                                values = list_plugin[1]
                                versions = []
                                library_name = plugin
                                for value in values:
                                    if 'version' in value:
                                        if isinstance(value['version'], list):
                                            versions.extend(value['version'])
                                        else:
                                            versions.append(value['version'])
                                    if 'string' in value:
                                        library_name = str(value['string'])
                                self._send_detected_fingerprints(
                                    name, port, schema, library_name, versions)
                    else:
                        logger.warning('found result non list %s', result)
                logger.info(
                    'Scan is done Parsing the results from %s.', output_file.name)
        except OSError as e:
            logger.error(
                'Exception while processing %s with message %s', output_file, e)

    def _send_detected_fingerprints(self, name: str, port: Optional[int] = None, schema: Optional[str] = None,
                                    library_name: Optional[str] = None, versions: Optional[List] = None):
        """Emits the identified fingerprints.

        Args:
            name: The domain name or ip address.
            port: the port of the service where the fingerprint has been identified.
            schema: scehama of the service where the fingerprint has been identified
            library_name: Library name.
            versions: The versions identified by WhatWeb scanner.
        """
        logger.info('found fingerprint %s %s %s',
                    name, library_name, versions)
        fingerprint_type = FINGERPRINT_TYPE[
            library_name.lower()] if library_name.lower() in FINGERPRINT_TYPE else DEFAULT_FINGERPRINT
        if len(versions) > 0:
            for version in versions:
                msg_data = self._get_msg_data(
                    name, port, schema, library_name, version, fingerprint_type)
                self.emit(selector=LIB_SELECTOR, data=msg_data)
                self.report_vulnerability(
                    entry=kb.Entry(
                        title=VULNZ_TITLE,
                        risk_rating=VULNZ_ENTRY_RISK_RATING,
                        short_description=VULNZ_SHORT_DESCRIPTION,
                        description=VULNZ_DESCRIPTION,
                        references={},
                        security_issue=True,
                        privacy_issue=False,
                        has_public_exploit=False,
                        targeted_by_malware=False,
                        targeted_by_ransomware=False,
                        targeted_by_nation_state=False
                    ),
                    technical_detail=f'Found library `{library_name}`, version `{str(version)}`, '
                    f'of type `{fingerprint_type}` in target `{name}`',
                    risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)
        else:
            # No version is found.
            msg_data = self._get_msg_data(
                name, port, schema, library_name, None, fingerprint_type)
            self.emit(selector=LIB_SELECTOR, data=msg_data)
            self.report_vulnerability(
                entry=kb.Entry(
                    title=VULNZ_TITLE,
                    risk_rating=VULNZ_ENTRY_RISK_RATING,
                    short_description=VULNZ_SHORT_DESCRIPTION,
                    description=VULNZ_DESCRIPTION,
                    references={},
                    security_issue=True,
                    privacy_issue=False,
                    has_public_exploit=False,
                    targeted_by_malware=False,
                    targeted_by_ransomware=False,
                    targeted_by_nation_state=False
                ),
                technical_detail=f'Found library `{library_name}` of type '
                f'`{fingerprint_type}` in target `{name}`',
                risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)

    def _get_msg_data(self, name, port: Optional[int] = None, schema: Optional[str] = None,
                      library_name: Optional[str] = None, version: Optional[str] = None,
                      fingerprint_type: Optional[str] = None):
        """Prepare  data of the library proto message to be emited."""
        msg_data = {}
        if name is not None:
            msg_data['name'] = name
        if port is not None:
            msg_data['port'] = port
        if schema is not None:
            msg_data['schema'] = schema
        if library_name is not None:
            msg_data['library_name'] = library_name
        if fingerprint_type is not None:
            msg_data['library_type'] = fingerprint_type
        if version is not None:
            msg_data['library_version'] = str(version)
            detail = f'Found library `{library_name}`, version `{str(version)}`, of type'
            detail = f'{detail} `{fingerprint_type}` in target `{name}`'
            msg_data['detail'] = detail
        else:
            detail = f'Found library `{library_name}`, of type `{fingerprint_type}`'
            detail = f'{detail} in target `{name}`'
            msg_data['detail'] = detail
        return msg_data


if __name__ == '__main__':
    logger.info('WhatWeb agent starting ...')
    AgentWhatWeb.main()
