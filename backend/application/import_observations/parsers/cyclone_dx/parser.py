import base64
import json
import re
import subprocess
from json import dumps, load
from typing import Optional

from django.core.files.base import File
from trycast import trycast

from application.core.models import Branch, Observation
from application.core.types import Severity
from application.import_observations.parsers.base_parser import (
    BaseFileParser,
    BaseParser,
)
from application.import_observations.parsers.cyclone_dx.dependencies import (
    get_component_dependencies,
)
from application.import_observations.parsers.cyclone_dx.types import Component, Metadata
from application.import_observations.types import Parser_Type


class CycloneDXParser(BaseParser, BaseFileParser):
    @classmethod
    def get_name(cls) -> str:
        return "CycloneDX"

    @classmethod
    def get_type(cls) -> str:
        return Parser_Type.TYPE_SCA

    def check_format(self, file: File) -> tuple[bool, list[str], dict]:
        try:
            data = load(file)
        except Exception:
            return False, ["File is not valid JSON"], {}

        bom_format = data.get("bomFormat")
        if bom_format != "CycloneDX":
            return False, ["File is not a CycloneDX SBOM"], {}

        return True, [], data

    def get_observations(
        self, data: dict, branch: Optional[Branch]
    ) -> list[Observation]:
        metadata = self._get_metadata(data)
        sbom_data = None
        image_location = (
            "oci.stackable.tech/sdp/"
            + metadata.container_name
            + ":"
            + metadata.container_tag
        )
        extract_sbom_cmd = [
            "cosign",
            "verify-attestation",
            "--type",
            "cyclonedx",
            "--certificate-identity-regexp",
            "^https://github.com/stackabletech/.+/.github/workflows/.+@.+",
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            image_location,
        ]
        print(" ".join(extract_sbom_cmd))

        result = subprocess.run(
            extract_sbom_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode == 0:
            cosign_output = json.loads(result.stdout.decode("utf-8"))
            payload = base64.b64decode(cosign_output["payload"]).decode("utf-8")
            sbom_data = json.loads(payload)["predicate"]

        components = self._get_components(sbom_data)
        observations = self._create_observations(
            sbom_data, data, components, metadata, branch
        )

        return observations

    def _get_components(self, data: dict) -> dict[str, Component]:
        components = {}

        root_component = self._get_root_component(data)
        if root_component:
            components[root_component.bom_ref] = root_component

        sbom_components = data.get("components", [])
        for sbom_component in sbom_components:
            component = self._get_component(sbom_component)
            if component:
                components[component.bom_ref] = component

        return components

    def _get_root_component(self, data: dict) -> Optional[Component]:
        metadata_component = data.get("metadata", {}).get("component")
        if not metadata_component:
            return None

        return self._get_component(metadata_component)

    def _get_component(self, component_data: dict[str, str]) -> Optional[Component]:
        if not component_data.get("bom-ref"):
            return None

        return Component(
            bom_ref=component_data.get("bom-ref", ""),
            name=component_data.get("name", ""),
            version=component_data.get("version", ""),
            type=component_data.get("type", ""),
            purl=component_data.get("purl", ""),
            cpe=component_data.get("cpe", ""),
            json=component_data,
        )

    def _create_observations(  # pylint: disable=too-many-locals
        self,
        sbom_data: Optional[dict],
        data: dict,
        components: dict[str, Component],
        metadata: Metadata,
        branch: Optional[Branch],
    ) -> list[Observation]:
        observations = []
        component_dependencies_cache: dict[str, tuple[str, list[dict]]] = {}

        for vulnerability in data.get("vulnerabilities", []):
            vulnerability_id = vulnerability.get("id")
            cvss3_score, cvss3_vector = self._get_cvss3(vulnerability)
            severity = ""
            if not cvss3_score:
                severity = self._get_highest_severity(vulnerability)
            cwe = self._get_cwe(vulnerability)
            description = vulnerability.get("description")
            detail = vulnerability.get("detail")
            if detail:
                description += f"\n\n{detail}"
            recommendation = vulnerability.get("recommendation")
            for affected in vulnerability.get("affects", []):
                ref = affected.get("ref")
                if ref:
                    component = components.get(ref)
                    if component:
                        title = vulnerability_id

                        if component.bom_ref in component_dependencies_cache:
                            (
                                observation_component_dependencies,
                                translated_component_dependencies,
                            ) = component_dependencies_cache[component.bom_ref]
                        else:
                            (
                                observation_component_dependencies,
                                translated_component_dependencies,
                            ) = get_component_dependencies(
                                data, components, component, metadata, sbom_data
                            )
                            component_dependencies_cache[component.bom_ref] = (
                                observation_component_dependencies,
                                translated_component_dependencies,
                            )

                        component_location = self._get_component_location(
                            component.json
                        )

                        patched_versions = self._get_patched_versions(
                            component, recommendation
                        )

                        observation_found = Observation.objects.filter(
                            title=title,
                            branch=branch,
                            origin_component_name=component.name,
                            origin_component_version=component.version,
                        ).exists()

                        if observation_found:
                            print(
                                "Observation already found: "
                                f"{title} - {component.name} - {component.version} - {metadata.scanner} - "
                                f"{metadata.container_name} - {metadata.container_tag}"
                            )
                            continue

                        observation = Observation(
                            title=title,
                            description=description,
                            recommendation=recommendation,
                            parser_severity=severity,
                            vulnerability_id=vulnerability_id,
                            origin_component_name=component.name,
                            origin_component_version=component.version,
                            origin_component_purl=component.purl,
                            origin_component_cpe=component.cpe,
                            origin_component_dependencies=observation_component_dependencies,
                            cvss3_score=cvss3_score,
                            cvss3_vector=cvss3_vector,
                            cwe=cwe,
                            scanner=metadata.scanner,
                            origin_docker_image_name=metadata.container_name,
                            origin_docker_image_tag=metadata.container_tag,
                            origin_docker_image_digest=metadata.container_digest,
                            origin_source_file=metadata.file,
                            origin_component_location=component_location,
                            patched_in_versions=patched_versions,
                            patch_available=bool(patched_versions),
                        )

                        self._add_references(vulnerability, observation)

                        self._add_evidences(
                            vulnerability,
                            component,
                            observation,
                            translated_component_dependencies,
                        )

                        observations.append(observation)

        return observations

    def _get_metadata(self, data: dict) -> Metadata:
        scanner = ""
        container_name = ""
        container_tag = ""
        container_digest = ""
        file = ""

        tools = data.get("metadata", {}).get("tools")
        if tools:
            if isinstance(tools, dict):
                components_or_services = tools.get("components", [])
                if not components_or_services:
                    components_or_services = tools.get("services", [])
                if components_or_services:
                    scanner = components_or_services[0].get("name", "")
                    version = components_or_services[0].get("version")
                    if version:
                        scanner += " / " + version
            if isinstance(tools, list):
                scanner = tools[0].get("name", "")
                version = tools[0].get("version")
                if version:
                    scanner += " / " + version

        component_type = data.get("metadata", {}).get("component", {}).get("type")
        component_name = data.get("metadata", {}).get("component", {}).get("name", "")
        component_version = (
            data.get("metadata", {}).get("component", {}).get("version", "")
        )
        if component_type == "container":
            container_name = component_name
            if component_version and component_version.startswith("sha256:"):
                container_digest = component_version
            elif component_version:
                container_tag = component_version
        if component_type == "file":
            file = component_name

        return Metadata(
            scanner=scanner,
            container_name=container_name,
            container_tag=container_tag,
            container_digest=container_digest,
            file=file,
        )

    def _get_cvss3(self, vulnerability):
        ratings = vulnerability.get("ratings", [])
        if ratings:
            cvss3_score = 0
            cvss3_vector = None
            for rating in ratings:
                method = rating.get("method")
                if method and method.lower().startswith("cvssv3"):
                    current_cvss3_score = rating.get("score", 0)
                    if current_cvss3_score > cvss3_score:
                        cvss3_score = current_cvss3_score
                        cvss3_vector = rating.get("vector")
            if cvss3_score > 0:
                return cvss3_score, cvss3_vector
        return None, None

    def _get_highest_severity(self, vulnerability):
        current_severity = Severity.SEVERITY_UNKOWN
        current_numerical_severity = 999
        ratings = vulnerability.get("ratings", [])
        if ratings:
            for rating in ratings:
                severity = rating.get("severity", Severity.SEVERITY_UNKOWN).capitalize()
                numerical_severity = Severity.NUMERICAL_SEVERITIES.get(severity, 99)
                if numerical_severity < current_numerical_severity:
                    current_severity = severity
        return current_severity

    def _get_cwe(self, vulnerability):
        cwes = vulnerability.get("cwes", [])
        if len(cwes) >= 1:
            return cwes[0]

        return None

    def _add_references(self, vulnerability: dict, observation: Observation) -> None:
        advisories = vulnerability.get("advisories", [])
        if advisories:
            for advisory in advisories:
                observation.unsaved_references.append(advisory.get("url"))

    def _add_evidences(
        self,
        vulnerability: dict,
        component: Component,
        observation: Observation,
        translated_component_dependencies: list[dict],
    ):
        evidence = []
        evidence.append("Vulnerability")
        evidence.append(dumps(vulnerability))
        observation.unsaved_evidences.append(evidence)
        evidence = []
        evidence.append("Component")
        evidence.append(dumps(component.json))
        observation.unsaved_evidences.append(evidence)

        if translated_component_dependencies:
            evidence = []
            evidence.append("Dependencies")
            evidence.append(dumps(translated_component_dependencies))
            observation.unsaved_evidences.append(evidence)

    def _get_component_location(self, component_json: dict[str, str]) -> str:
        properties_as_list = trycast(
            list[dict[str, str]], component_json.get("properties", "")
        )
        if properties_as_list is not None:
            for prop in properties_as_list:
                if prop.get("name") == "syft:location:0:path":
                    return prop.get("value")
                if prop.get("name") == "aquasecurity:trivy:FilePath":
                    return prop.get("value")
        return ""

    def _get_patched_versions(self, component: Component, recommendation: str) -> str:
        if not recommendation:
            return ""

        group = re.search(
            r"Upgrade (\S+:)?" + component.name + r" to version ([a-z0-9\.\-_\s,]+)",
            recommendation,
        )
        if group:
            return group.group(2)

        return ""
