"""WhatWeb Agent: Agent responsible for finger-printing a website."""
import io
import json
import logging
import subprocess
import tempfile

from ostorlab.agent import agent
from ostorlab.agent import message as msg
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from rich import logging as rich_logging

logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True), ],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

VULNZ_TITLE = 'Web Tech Stack Fingerprint'
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
LIB_SELECTOR = 'v3.fingerprint.domain_name.library'


class AgentWhatWeb(agent.Agent, agent_report_vulnerability_mixin.AgentReportVulnMixin):
    """Agent responsible for finger-printing a website."""

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info('processing message of selector : %s', message.selector)
        with tempfile.NamedTemporaryFile() as fp:
            self._start_scan(message.data['name'], fp.name)
            self._parse_emit_result(message.data['name'], fp)

    def _start_scan(self, domain_name: str, output_file: str):
        """Run a whatweb scan using python subprocess.

        Args:
            domain_name: Target domain name.
            output_file: The output file to save the scan result.
        """
        logger.info('Staring a new scan for %s .', domain_name)
        whatweb_command = [WHATWEB_PATH, f'--log-json-verbose={output_file}', domain_name]
        subprocess.run(whatweb_command, cwd=WHATWEB_DIRECTORY, check=True)

    def _parse_emit_result(self, domain_name: str, output_file: io.BytesIO):
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
                                self._send_detected_fingerprints(domain_name, library_name, versions)
                    else:
                        logger.warning('found result non list %s', result)
                logger.info('Scan is done Parsing the results from %s.', output_file.name)
        except OSError as e:
            logger.error('Exception while processing %s with message %s', output_file, e)

    def _send_detected_fingerprints(self, domain_name: str, library_name: str, versions: list):
        """Emits the identified fingerprints.

        Args:
            domain_name: The domain name.
            library_name: Library name.
            versions: The versions identified by WhatWeb scanner.
        """
        logger.info('found fingerprint %s %s %s', domain_name, library_name, versions)
        fingerprint_type = FINGERPRINT_TYPE[
            library_name.lower()] if library_name.lower() in FINGERPRINT_TYPE else DEFAULT_FINGERPRINT
        if len(versions) > 0:
            for version in versions:
                msg_data = {
                    'domain_name': domain_name,
                    'library_name': library_name,
                    'library_version': str(version),
                    'library_type': fingerprint_type
                }
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
                    f'of type `{fingerprint_type}` in domain `{domain_name}`',
                    risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)
        else:
            # No version is found.
            msg_data = {
                'domain_name': domain_name,
                'library_name': library_name,
                'library_version': '',
                'library_type': fingerprint_type
            }
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
                f'`{fingerprint_type}` in domain `{domain_name}`',
                risk_rating=agent_report_vulnerability_mixin.RiskRating.INFO)


if __name__ == '__main__':
    logger.info('WhatWeb agent starting ...')
    AgentWhatWeb.main()
