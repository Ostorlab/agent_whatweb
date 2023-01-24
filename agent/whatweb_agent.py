"""WhatWeb Agent: Agent responsible for finger-printing a website."""
import abc
import io
import json
import logging
import subprocess
import ipaddress
import tempfile
from typing import List, Optional, Dict, Any
from urllib import parse
import dataclasses

from ostorlab.agent import agent
from ostorlab.agent.message import message as msg
from ostorlab.agent.kb import kb
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import ipv6 as ipv6_asset
from rich import logging as rich_logging

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[
        rich_logging.RichHandler(rich_tracebacks=True),
    ],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)

VULNZ_TITLE = "Tech Stack Fingerprint"
VULNZ_ENTRY_RISK_RATING = "INFO"
VULNZ_SHORT_DESCRIPTION = "List of web technologies recognized"
VULNZ_DESCRIPTION = """Lists web technologies including content management systems(CMS), blogging platforms,
statistic/analytics packages, JavaScript libraries, web servers, embedded devices, version numbers, email addresses,
account IDs, web framework modules, SQL errors, and more."""

# These are verbose non-preferred plugins.
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
    "Strict-Transport-Security",
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

DEFAULT_FINGERPRINT = "BACKEND_COMPONENT"

FINGERPRINT_TYPE = {"jquery": "JAVASCRIPT_LIBRARY"}

WHATWEB_PATH = "./whatweb"
WHATWEB_DIRECTORY = "/WhatWeb"
LIB_SELECTOR = "v3.fingerprint.domain_name.service.library"
SCHEME_TO_PORT = {"http": 80, "https": 443}


class BaseTarget(abc.ABC):
    @property
    @abc.abstractmethod
    def target(self):
        raise NotImplementedError()


@dataclasses.dataclass
class DomainTarget(BaseTarget):
    name: str
    schema: Optional[str] = None
    port: Optional[int] = None

    @property
    def target(self):
        url = ""
        if self.schema is not None:
            url += f"{self.schema}://"

        url += self.name

        if self.port is not None:
            url += f":{self.port}"

        return url


@dataclasses.dataclass
class IPTarget(BaseTarget):
    name: str
    version: int
    schema: Optional[str] = None
    port: Optional[int] = None

    @property
    def target(self):
        url = ""
        if self.schema is not None:
            url += f"{self.schema}://"

        url += self.name

        if self.port is not None:
            url += f":{self.port}"

        return url


class AgentWhatWeb(
    agent.Agent, vuln_mixin.AgentReportVulnMixin, persist_mixin.AgentPersistMixin
):
    """Agent responsible for fingerprinting a website."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:

        agent.Agent.__init__(self, agent_definition, agent_settings)
        vuln_mixin.AgentReportVulnMixin.__init__(self)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info("processing message of selector : %s", message.selector)
        targets = self._prepare_targets(message)
        if self._should_target_be_processed(message) is False:
            return

        for target in targets:
            try:
                with tempfile.NamedTemporaryFile() as fp:
                    self._start_scan(target, fp.name)
                    self._parse_emit_result(target, io.BytesIO(fp.read()))
            except subprocess.CalledProcessError as e:
                logger.error(e)

    def _prepare_targets(self, message: msg.Message) -> List[BaseTarget]:
        """Returns a list of target objects to be scanned."""
        targets: List[DomainTarget | IPTarget] = []
        domain_targets = self._prepare_domain_targets(message)
        ip_targets = self._prepare_ip_targets(message)
        targets.extend(domain_targets)
        targets.extend(ip_targets)
        return targets

    def _get_port(self, message: msg.Message) -> int:
        """Returns the port to be used for the target."""
        if message.data.get("port") is not None:
            return int(message.data["port"])
        else:
            return int(self.args["port"])

    def _get_schema(self, message: msg.Message) -> str:
        """Returns the schema to be used for the target."""
        if message.data.get("schema") is not None:
            return str(message.data["schema"])
        elif message.data.get("protocol") is not None:
            return str(message.data["protocol"])
        else:
            return str(self.args["schema"])

    def _prepare_domain_targets(self, message: msg.Message) -> List[DomainTarget]:
        """Returns a list of domain targets to be scanned."""
        targets: List[DomainTarget] = []
        if message.data.get("url") is not None:
            url_target = self._get_target_from_url(message.data["url"])
            targets.append(url_target)
        elif message.data.get("name") is not None:
            domain_name = message.data["name"]
            domain_target = DomainTarget(
                name=domain_name,
                schema=self._get_schema(message),
                port=self._get_port(message),
            )
            targets.append(domain_target)
        return targets

    def _prepare_ip_targets(self, message: msg.Message) -> List[IPTarget]:
        """Returns a list of ip targets to be scanned."""
        targets: List[IPTarget] = []
        host = message.data.get("host")
        mask = message.data.get("mask")

        if host is None:
            return targets

        if mask is not None:
            try:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                for address in addresses.hosts():
                    targets.append(
                        IPTarget(
                            name=str(address),
                            version=address.version,
                            schema=self._get_schema(message),
                            port=self._get_port(message),
                        )
                    )
            except ValueError as e:
                logger.error("Invalid IP or mask. %s", e)
        else:
            try:
                addresses = ipaddress.ip_network(host, strict=False)
                for address in addresses.hosts():
                    targets.append(
                        IPTarget(
                            name=str(address),
                            version=address.version,
                            schema=self._get_schema(message),
                            port=self._get_port(message),
                        )
                    )
            except ValueError as e:
                logger.error("Invalid IP. %s", e)

        return targets

    def _should_target_be_processed(self, message: msg.Message) -> bool:
        """Checks if the target has already been processed before, relies on the redis server."""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            if message.data.get("url") is not None:
                target = self._get_target_from_url(message.data["url"])
                unicity_check_key = f"{target.schema}_{target.name}_{target.port}"
            elif message.data.get("name") is not None:
                port = self._get_port(message)
                schema = self._get_schema(message)
                domain = message.data["name"]
                unicity_check_key = f"{schema}_{domain}_{port}"

            if self.set_add(b"agent_whatweb_asset", unicity_check_key) is True:
                return True
            else:
                logger.info(
                    "target %s/ was processed before, exiting", unicity_check_key
                )
                return False
        elif message.data.get("host") is not None:
            host = message.data.get("host")
            mask = message.data.get("mask")
            schema = self._get_schema(message)
            port = self._get_port(message)
            if mask is not None:
                addresses = ipaddress.ip_network(f"{host}/{mask}", strict=False)
                result = self.add_ip_network(
                    "agent_whois_ip_asset",
                    addresses,
                    lambda net: f"{schema}_{net}_{port}",
                )
                if result is False:
                    logger.info("target %s was processed before, exiting", addresses)
            else:
                result = self.set_add("agent_whois_ip_asset", f"{schema}_{host}_{port}")
                if result is False:
                    logger.info("target %s was processed before, exiting", host)
            return result
        else:
            logger.error("Unknown message type %s", message.data)
            return False

    def _get_target_from_url(self, url: str) -> DomainTarget:
        """Compute schema and port from a URL"""
        parsed_url = parse.urlparse(url)
        schema = str(parsed_url.scheme) or str(self.args["schema"])
        domain_name = parse.urlparse(url).netloc
        port = 0
        if len(parsed_url.netloc.split(":")) > 1:
            domain_name = parsed_url.netloc.split(":")[0]
            port = (
                int(parsed_url.netloc.split(":")[-1])
                if parsed_url.netloc.split(":")[-1] is not None
                else 0
            )
        port = port or SCHEME_TO_PORT[schema] or self.args["port"]
        target = DomainTarget(name=domain_name, schema=schema, port=port)
        return target

    def _start_scan(self, target: DomainTarget | IPTarget, output_file: str) -> None:
        """Run a whatweb scan using python subprocess.

        Args:
            target: Targeted domain name or IP address.
            output_file: The output file to save the scan result.
        """
        logger.info("Staring a new scan for %s .", target.name)
        whatweb_command = [
            WHATWEB_PATH,
            f"--log-json-verbose={output_file}",
            target.target,
        ]
        subprocess.run(whatweb_command, cwd=WHATWEB_DIRECTORY, check=True)

    def _parse_emit_result(
        self, target: DomainTarget | IPTarget, output_file: io.BytesIO
    ) -> None:
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
                                    if "version" in value:
                                        if isinstance(value["version"], list):
                                            versions.extend(value["version"])
                                        else:
                                            versions.append(value["version"])
                                    if "string" in value:
                                        library_name = str(value["string"])
                                self._send_detected_fingerprints(
                                    target, library_name, versions
                                )
                    else:
                        logger.warning("found result non list %s", result)
                logger.info("Scan is done Parsing the results from %s.", output_file)
        except OSError as e:
            logger.error(
                "Exception while processing %s with message %s", output_file, e
            )

    def _prepare_vulnerable_target_data(
        self, target: DomainTarget | IPTarget
    ) -> vuln_mixin.VulnerabilityLocation:
        """Returns the target data where the fingerprint was found."""
        metadata_type = vuln_mixin.MetadataType.PORT
        metadata_value = str(target.port)
        metadata = [
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=metadata_type, value=metadata_value
            )
        ]
        if isinstance(target, DomainTarget):
            asset = domain_asset.DomainName(name=target.name)
            return vuln_mixin.VulnerabilityLocation(asset=asset, metadata=metadata)
        elif isinstance(target, IPTarget):
            if target.version == 4:
                ip_v4_asset = ipv4_asset.IPv4(host=target.name, version=4, mask="32")
                return vuln_mixin.VulnerabilityLocation(
                    asset=ip_v4_asset, metadata=metadata
                )
            else:
                ip_v6_asset = ipv6_asset.IPv6(host=target.name, version=6, mask="128")
                return vuln_mixin.VulnerabilityLocation(
                    asset=ip_v6_asset, metadata=metadata
                )
        else:
            raise NotImplementedError(f"type target { type(target)} not implemented")

    def _send_detected_fingerprints(
        self,
        target: DomainTarget | IPTarget,
        library_name: Optional[str] = None,
        versions: Optional[List[Optional[str]]] = None,
    ) -> None:
        """Emits the identified fingerprints.

        Args:
            target: targeted Domain or IP address.
            library_name: Library name.
            versions: The versions identified by WhatWeb scanner.
        """
        logger.info("Found fingerprint %s %s %s", target.name, library_name, versions)
        fingerprint_type = (
            FINGERPRINT_TYPE[library_name.lower()]
            if (library_name is not None and library_name.lower() in FINGERPRINT_TYPE)
            else DEFAULT_FINGERPRINT
        )

        vulnerable_target_data = self._prepare_vulnerable_target_data(target)

        if versions is not None and len(versions) > 0:
            for version in versions:
                msg_data = self._get_msg_data(
                    target, library_name, version, fingerprint_type
                )
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
                        targeted_by_nation_state=False,
                    ),
                    technical_detail=f"Found library `{library_name}`, version `{str(version)}`, "
                    f"of type `{fingerprint_type}` in target `{target.name}`",
                    risk_rating=vuln_mixin.RiskRating.INFO,
                    vulnerability_location=vulnerable_target_data,
                )
        else:
            # No version is found.
            msg_data = self._get_msg_data(target, library_name, None, fingerprint_type)
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
                    targeted_by_nation_state=False,
                ),
                technical_detail=f"Found library `{library_name}` of type "
                f"`{fingerprint_type}` in target `{target.name}`",
                risk_rating=vuln_mixin.RiskRating.INFO,
                vulnerability_location=vulnerable_target_data,
            )

    def _get_msg_data(
        self,
        target: DomainTarget | IPTarget,
        library_name: Optional[str] = None,
        version: Optional[str] = None,
        fingerprint_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Prepare  data of the library proto message to be emited."""
        msg_data: Dict[str, Any] = {}
        if target.name is not None:
            msg_data["name"] = target.name
        if target.port is not None:
            msg_data["port"] = target.port
        if target.schema is not None:
            msg_data["schema"] = target.schema
        if library_name is not None:
            msg_data["library_name"] = library_name
        if fingerprint_type is not None:
            msg_data["library_type"] = fingerprint_type
        if version is not None:
            msg_data["library_version"] = str(version)
            detail = (
                f"Found library `{library_name}`, version `{str(version)}`, of type"
            )
            detail = f"{detail} `{fingerprint_type}` in target `{target.name}`"
            msg_data["detail"] = detail
        else:
            detail = f"Found library `{library_name}`, of type `{fingerprint_type}`"
            detail = f"{detail} in target `{target.name}`"
            msg_data["detail"] = detail
        return msg_data


if __name__ == "__main__":
    logger.info("WhatWeb agent starting ...")
    AgentWhatWeb.main()
