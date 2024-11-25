import base64
import json
import re
import subprocess
from collections import defaultdict
from json import dumps, load
from typing import Any, Optional

from django.core.files.base import File
from trycast import trycast

from application.core.models import Observation
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
from application.licenses.models import License_Component


class CycloneDXParser(BaseParser, BaseFileParser):
    def __init__(self):
        self.metadata = Metadata("", "", "", "", "")
        self.components: dict[str, Component] = {}

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

    def get_observations(self, data: dict) -> list[Observation]:
        self.metadata = self._get_metadata(data)
        sbom_data = None

        image_location = (
            "oci.stackable.tech/sdp/"
            + self.metadata.container_name
            + ":"
            + self.metadata.container_tag
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

        self.components = self._get_components(data, sbom_data)
        observations = self._create_observations(data, sbom_data)

        return observations

    def get_license_components(self, data) -> list[License_Component]:
        if not self.components:
            self.components = self._get_components(data, None)
        if not self.metadata:
            self.metadata = self._get_metadata(data)

        components = []
        licenses_exist = False

        for component in self.components.values():
            if component.unknown_license:
                licenses_exist = True

        if licenses_exist:
            for component in self.components.values():
                if component.unknown_license:
                    licenses_exist = True

                observation_component_dependencies, _ = get_component_dependencies(
                    data, self.components, component, defaultdict(list)
                )
                model_component = License_Component(
                    name=component.name,
                    version=component.version,
                    purl=component.purl,
                    cpe=component.cpe,
                    dependencies=observation_component_dependencies,
                )
                model_component.unsaved_license = component.unknown_license
                self._add_license_component_evidence(component, model_component)
                components.append(model_component)

        return components

    def _add_license_component_evidence(
        self,
        component: Component,
        license_component: License_Component,
    ) -> None:
        evidence = []
        evidence.append("Component")
        evidence.append(dumps(component.json))
        license_component.unsaved_evidences.append(evidence)

    def _get_components(self, data: dict, sbom_data: Optional[dict]) -> dict[str, Component]:
        components_dict = {}
        components_list: list[Component] = []

        root_components = self._get_root_component_with_subs(data)
        components_list.extend(root_components)

        sbom_components = data.get("components", [])
        for sbom_component in sbom_components:
            components = self._get_sbom_component_with_subs(sbom_component)
            components_list.extend(components)

        if sbom_data:
            root_components = self._get_root_component_with_subs(sbom_data)
            components_list.extend(root_components)

            sbom_components = sbom_data.get("components", [])
            for sbom_component in sbom_components:
                components = self._get_sbom_component_with_subs(sbom_component)
                components_list.extend(components)

        for component in components_list:
            components_dict[component.bom_ref] = component

        return components_dict

    def _get_root_component_with_subs(self, data: dict) -> list[Component]:
        metadata_component = data.get("metadata", {}).get("component")
        if not metadata_component:
            return []

        return self._get_sbom_component_with_subs(metadata_component)

    def _get_sbom_component_with_subs(
        self, component_data: dict[str, Any]
    ) -> list[Component]:
        components: list[Component] = []
        component = self._get_component(component_data)
        if component:
            components.append(component)

        for sub_component in component_data.get("components", []):
            components.extend(self._get_sbom_component_with_subs(sub_component))

        return components

    def _get_component(self, component_data: dict[str, Any]) -> Optional[Component]:
        if not component_data.get("bom-ref"):
            return None

        unknown_licenses = []
        licenses = component_data.get("licenses", [])
        if licenses and licenses[0].get("expression"):
            unknown_licenses.append(licenses[0].get("expression"))
        else:
            for my_license in licenses:
                component_license = my_license.get("license", {}).get("id")
                if component_license and component_license not in unknown_licenses:
                    unknown_licenses.append(component_license)

                component_license = my_license.get("license", {}).get("name")
                if component_license and component_license not in unknown_licenses:
                    unknown_licenses.append(component_license)

        return Component(
            bom_ref=component_data.get("bom-ref", ""),
            name=component_data.get("name", ""),
            version=component_data.get("version", ""),
            type=component_data.get("type", ""),
            purl=component_data.get("purl", ""),
            cpe=component_data.get("cpe", ""),
            json=component_data,
            unknown_license=", ".join(unknown_licenses),
        )

    def _translate_component(self, bom_ref: str) -> str:
        component = self.components.get(bom_ref, None)
        if not component:
            return ""

        if component.version:
            component_name_version = f"{component.name}:{component.version}"
        else:
            component_name_version = component.name

        return component_name_version

    def _create_observations(  # pylint: disable=too-many-locals
        self,
        data: dict,
        sbom_data: Optional[dict],
    ) -> list[Observation]:
        observations = []
        component_dependencies_cache: dict[str, tuple[str, list[dict]]] = {}

        if not sbom_data:
            sbom_data = data

        dependencies = sbom_data.get("dependencies", [])

        reverse_dep_map = defaultdict(list)
        for entry in dependencies:
            for dep in entry.get("dependsOn", []):
                reverse_dep_map[dep].append(
                    entry["ref"]
                )  # Add a relation from the dependency it's "parent"

        relevant_components = set()
        for vulnerability in data.get("vulnerabilities", []):
            for affected in vulnerability.get("affects", []):
                ref = affected.get("ref")
                if ref:
                    component = self.components.get(ref)
                    if component:
                        relevant_components.add(component.bom_ref)

        dependency_paths: dict[str, list[str]] = defaultdict(list)

        # Get all paths from the root components in the dependency tree to the relevant components
        for relevant_component in relevant_components:
            stack: list[tuple[str, Optional[str]]] = [(relevant_component, None)]
            visited = set()
            if relevant_component not in dependency_paths:
                dependency_paths[relevant_component] = []
            while stack:
                current, previous = stack.pop()
                if not current:
                    continue

                if previous:
                    path = f"{self._translate_component(current)} --> {self._translate_component(previous)}"
                    if path not in dependency_paths[relevant_component]:
                        dependency_paths[relevant_component].append(path)
                if current in visited:
                    continue
                visited.add(current)
                if current in reverse_dep_map:
                    for parent in reverse_dep_map[current]:
                        stack.append((parent, current))

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
                    component = self.components.get(ref)
                    print(f"Processing vulnerability: {vulnerability_id}")
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
                                sbom_data,
                                self.components,
                                component,
                                dependency_paths,
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
                            scanner=self.metadata.scanner,
                            origin_docker_image_name=self.metadata.container_name,
                            origin_docker_image_tag=self.metadata.container_tag,
                            origin_docker_image_digest=self.metadata.container_digest,
                            origin_source_file=self.metadata.file,
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
        current_severity = Severity.SEVERITY_UNKNOWN
        current_numerical_severity = 999
        ratings = vulnerability.get("ratings", [])
        if ratings:
            for rating in ratings:
                severity = rating.get(
                    "severity", Severity.SEVERITY_UNKNOWN
                ).capitalize()
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
