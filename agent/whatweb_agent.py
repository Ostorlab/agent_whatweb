"""WhatWeb Agent: Agent responsible for finger-printing a website."""

import abc
import dataclasses
import io
import ipaddress
import json
import logging
import re
import subprocess
import tempfile
from typing import List, Optional, Dict, Any
from urllib import parse

from ostorlab.agent import agent
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as msg
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from ostorlab.assets import domain_name as domain_asset
from ostorlab.assets import ipv4 as ipv4_asset
from ostorlab.assets import ipv6 as ipv6_asset
from ostorlab.runtimes import definitions as runtime_definitions
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
DOMAIN_NAME_LIB_SELECTOR = "v3.fingerprint.domain_name.service.library"
IP_V4_LIB_SELECTOR = "v3.fingerprint.ip.v4.service.library"
IP_V6_LIB_SELECTOR = "v3.fingerprint.ip.v6.service.library"
SCHEME_TO_PORT = {"http": 80, "https": 443}
IPV4_CIDR_LIMIT = 16
IPV6_CIDR_LIMIT = 112


class BaseTarget(abc.ABC):
    """Base target with a target property for use by the Whatweb binary."""

    @property
    @abc.abstractmethod
    def target(self) -> str:
        """Prepare target."""
        raise NotImplementedError()


@dataclasses.dataclass
class DomainTarget(BaseTarget):
    """Domain target."""

    name: str
    schema: Optional[str] = None
    port: Optional[int] = None

    @property
    def target(self) -> str:
        """Prepare target."""
        url = ""
        if self.schema is not None:
            url += f"{self.schema}://"

        url += self.name

        if self.port is not None:
            url += f":{self.port}"

        return url


@dataclasses.dataclass
class IPTarget(BaseTarget):
    """IP target."""

    name: str
    version: int
    schema: Optional[str] = None
    port: Optional[int] = None

    @property
    def target(self) -> str:
        """Prepare target."""
        url = ""
        if self.schema is not None and self.schema in ("https", "http"):
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
        self._scope_domain_regex: Optional[str] = self.args.get("scope_domain_regex")

    def process(self, message: msg.Message) -> None:
        """Starts a whatweb scan, wait for the scan to finish,
        and emit the results.

        Args:
            message:  The message to process from ostorlab runtime.
        """
        logger.info("processing message of selector : %s", message.selector)
        targets = self._prepare_targets(message)
        logger.info("Generated targets %s", targets)
        if self._should_target_be_processed(message) is False:
            return

        for target in targets:
            try:
                logger.info("Scanning target %s", target)
                with tempfile.NamedTemporaryFile() as fp:
                    self._start_scan(target, fp.name)
                    self._parse_emit_result(target, io.BytesIO(fp.read()))
            except subprocess.CalledProcessError as e:
                logger.error("Error scanning target `%s`: %s", target, e)

    def _prepare_targets(self, message: msg.Message) -> List[IPTarget | DomainTarget]:
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
            if url_target is not None:
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
        if mask is None:
            network = ipaddress.ip_network(f"{host}")
        else:
            version = message.data.get("version")
            if version is None:
                try:
                    ip = ipaddress.ip_address(host)
                    version = ip.version
                except ValueError:
                    raise ValueError(f"Invalid IP address: {host}")
            if version not in (4, 6):
                raise ValueError(f"Incorrect ip version {version}.")
            elif version == 4 and int(mask) < IPV4_CIDR_LIMIT:
                raise ValueError(
                    f"Subnet mask below {IPV4_CIDR_LIMIT} is not supported."
                )
            elif version == 6 and int(mask) < IPV6_CIDR_LIMIT:
                raise ValueError(
                    f"Subnet mask below {IPV6_CIDR_LIMIT} is not supported."
                )
            network = ipaddress.ip_network(f"{host}/{mask}", strict=False)

        for address in network.hosts():
            targets.append(
                IPTarget(
                    name=str(address),
                    version=address.version,
                    schema=self._get_schema(message),
                    port=self._get_port(message),
                )
            )
        return targets

    def _is_domain_in_scope(
        self,
        message: msg.Message,
    ) -> bool:
        """Check if a domain is in the scan scope with a regular expression."""
        if self._scope_domain_regex is None:
            return True
        domain = ""
        if message.data.get("url") is not None:
            extracted_domain = self._get_target_from_url(message.data["url"])
            if extracted_domain is not None:
                domain = extracted_domain.name
        if message.data.get("name") is not None:
            domain = message.data["name"]
        domain_in_scope = re.match(self._scope_domain_regex, domain)
        if domain_in_scope is None:
            logger.warning(
                "Domain %s is not in scanning scope %s",
                domain,
                self._scope_domain_regex,
            )
            return False
        else:
            return True

    def _get_web_target_unique_key(self, message: msg.Message) -> str | None:
        """Returns a unique key identifier to be used to check if the target was scanned before."""
        if message.data.get("url") is not None:
            extracted_target = self._get_target_from_url(message.data["url"])
            if extracted_target is not None:
                return f"{extracted_target.schema}_{extracted_target.name}_{extracted_target.port}"
        if message.data.get("name") is not None:
            port = self._get_port(message)
            schema = self._get_schema(message)
            domain = message.data["name"]
            return f"{schema}_{domain}_{port}"
        return None

    def _should_target_be_processed(self, message: msg.Message) -> bool:
        """Checks if the target has already been processed before, relies on the redis server."""
        if message.data.get("url") is not None or message.data.get("name") is not None:
            unique_key = self._get_web_target_unique_key(message)
            if unique_key is None:
                return False
            if self.set_add(b"agent_whatweb_asset", unique_key) is False:
                logger.info("target %s/ was processed before, exiting", unique_key)
                return False

            is_domain_in_scope = self._is_domain_in_scope(message)
            return is_domain_in_scope

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

    def _get_target_from_url(self, url: str) -> DomainTarget | None:
        """Compute schema and port from a URL"""
        parsed_url = parse.urlparse(url)
        if parsed_url.scheme not in SCHEME_TO_PORT:
            logger.warning("Unsupported schema %s", parsed_url.scheme)
            return None
        schema = str(parsed_url.scheme) or str(self.args["schema"])
        domain_name = parse.urlparse(url).netloc
        port = None
        if len(parsed_url.netloc.split(":")) > 1:
            domain_name = parsed_url.netloc.split(":")[0]
            port = (
                int(parsed_url.netloc.split(":")[-1])
                if parsed_url.netloc.split(":")[-1] is not None
                else 0
            )
        port = port or SCHEME_TO_PORT.get(schema) or self.args.get("port")
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
            raise NotImplementedError(f"type target {type(target)} not implemented")

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
                if isinstance(target, DomainTarget):
                    self.emit(selector=DOMAIN_NAME_LIB_SELECTOR, data=msg_data)
                elif isinstance(target, IPTarget) and target.version == 4:
                    self.emit(selector=IP_V4_LIB_SELECTOR, data=msg_data)
                elif isinstance(target, IPTarget) and target.version == 6:
                    self.emit(selector=IP_V6_LIB_SELECTOR, data=msg_data)

                dna = _prepare_vulnerability_dna(
                    vulnerability_location=vulnerable_target_data, vuln_data=msg_data
                )
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
                    technical_detail=f"Found fingerprint `{library_name}`, version `{str(version)}`, "
                    f"of type `{fingerprint_type}` in target `{target.name}`",
                    risk_rating=vuln_mixin.RiskRating.INFO,
                    vulnerability_location=vulnerable_target_data,
                    dna=dna,
                )
        else:
            # No version is found.
            msg_data = self._get_msg_data(target, library_name, None, fingerprint_type)
            if isinstance(target, DomainTarget):
                self.emit(selector=DOMAIN_NAME_LIB_SELECTOR, data=msg_data)
            elif isinstance(target, IPTarget) and target.version == 4:
                self.emit(selector=IP_V4_LIB_SELECTOR, data=msg_data)
            elif isinstance(target, IPTarget) and target.version == 6:
                self.emit(selector=IP_V6_LIB_SELECTOR, data=msg_data)

            dna = _prepare_vulnerability_dna(
                vulnerability_location=vulnerable_target_data, vuln_data=msg_data
            )
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
                technical_detail=f"Found fingerprint `{library_name}` of type "
                f"`{fingerprint_type}` in target `{target.name}`",
                risk_rating=vuln_mixin.RiskRating.INFO,
                vulnerability_location=vulnerable_target_data,
                dna=dna,
            )

    def _get_msg_data(
        self,
        target: DomainTarget | IPTarget,
        library_name: Optional[str] = None,
        version: Optional[str] = None,
        fingerprint_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Prepare  data of the library proto message to be emitted."""
        msg_data: Dict[str, Any] = {}
        if target.name is not None:
            if isinstance(target, DomainTarget):
                msg_data["name"] = target.name
                msg_data["schema"] = target.schema
            elif isinstance(target, IPTarget):
                msg_data["host"] = target.name
                msg_data["version"] = target.version
                msg_data["mask"] = "32" if target.version == 4 else "128"
        if target.port is not None:
            msg_data["port"] = target.port
        if library_name is not None:
            msg_data["library_name"] = library_name
        if fingerprint_type is not None:
            msg_data["library_type"] = fingerprint_type
        if version is not None:
            msg_data["library_version"] = str(version)
            detail = (
                f"Found fingerprint `{library_name}`, version `{str(version)}`, of type"
            )
            detail = f"{detail} `{fingerprint_type}` in target `{target.name}`"
            msg_data["detail"] = detail
        else:
            detail = f"Found fingerprint `{library_name}`, of type `{fingerprint_type}`"
            detail = f"{detail} in target `{target.name}`"
            msg_data["detail"] = detail
        return msg_data


def _prepare_vulnerability_dna(
    vulnerability_location: vuln_mixin.VulnerabilityLocation, vuln_data: dict[str, Any]
) -> str:
    """Prepare a `dna` instance with the unique_key and the aggregated reports."""
    dna_dict = {
        "vuln_data": vuln_data,
    }
    if vulnerability_location is not None:
        dna_dict["location"] = vulnerability_location.to_dict()  # type:ignore[assignment]

    dna = _sort_dict(dna_dict)
    return json.dumps(dna, sort_keys=True)


def _sort_dict(dictionary: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.
    Args:
        dictionary: The dictionary to sort.
    Returns:
        A sorted dictionary or list.
    """
    if isinstance(dictionary, dict):
        return {k: _sort_dict(v) for k, v in sorted(dictionary.items())}
    if isinstance(dictionary, list):
        return sorted(
            dictionary,
            key=lambda x: json.dumps(x, sort_keys=True)
            if isinstance(x, dict)
            else str(x),
        )
    return dictionary


if __name__ == "__main__":
    logger.info("WhatWeb agent starting ...")
    AgentWhatWeb.main()
