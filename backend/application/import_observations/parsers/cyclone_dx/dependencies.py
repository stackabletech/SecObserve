import logging
from collections import defaultdict
from typing import Optional

from application.import_observations.parsers.cyclone_dx.types import Component

logger = logging.getLogger("secobserve.import_observations.cyclone_dx.dependencies")


def get_component_dependencies(
    data: dict,
    components: dict[str, Component],
    component: Component,
    component_dependency_paths: dict[str, list[list[str]]],
) -> tuple[str, list[dict]]:
    component_dependencies: list[dict[str, str | list[str]]] = []

    _filter_component_dependencies(
        component.bom_ref,
        data.get("dependencies", []),
        component_dependencies,
    )
    translated_component_dependencies = []
    if component_dependencies:
        translated_component_dependencies = _translate_component_dependencies(
            component_dependencies, components
        )

    observation_component_dependencies = ""

    paths = component_dependency_paths.get(component.bom_ref, [])
    seen_relations = set()
    for path in paths:
        for i, node in enumerate(path):
            if i == 0:
                parent = node
                continue

            relation = f"{_translate_component(parent, components)} --> {_translate_component(node, components)}\n"

            parent = node
            if relation not in seen_relations:
                observation_component_dependencies += relation
                seen_relations.add(relation)

    if len(observation_component_dependencies) > 32768:
        observation_component_dependencies = (
            observation_component_dependencies[:32764] + " ..."
        )

    return observation_component_dependencies, translated_component_dependencies


def _filter_component_dependencies(
    bom_ref: str,
    dependencies: list[dict[str, str | list[str]]],
    component_dependencies: list[dict[str, str | list[str]]],
) -> None:
    for dependency in dependencies:
        if dependency in component_dependencies:
            continue
        depends_on = dependency.get("dependsOn", [])
        if bom_ref in depends_on:
            component_dependencies.append(dependency)
            _filter_component_dependencies(
                str(dependency.get("ref")), dependencies, component_dependencies
            )


def _translate_component_dependencies(
    component_dependencies: list[dict[str, str | list[str]]],
    components: dict[str, Component],
) -> list[dict]:
    translated_component_dependencies = []

    for component_dependency in component_dependencies:
        translated_component_dependency: dict[str, str | list[str]] = {}

        translated_component_dependency["ref"] = _translate_component(
            str(component_dependency.get("ref")), components
        )

        translated_component_dependencies_inner: list[str] = []
        for dependency in component_dependency.get("dependsOn", []):
            translated_component_dependencies_inner.append(
                _translate_component(dependency, components)
            )
        translated_component_dependencies_inner.sort()
        translated_component_dependency["dependsOn"] = (
            translated_component_dependencies_inner
        )

        translated_component_dependencies.append(translated_component_dependency)

    return translated_component_dependencies


def _translate_component(bom_ref: str, components: dict[str, Component]) -> str:
    component = components.get(bom_ref, None)
    if not component:
        logger.warning("Component with BOM ref %s not found", bom_ref)
        return ""

    if component.version:
        component_name_version = f"{component.name}:{component.version}"
    else:
        component_name_version = component.name

    return component_name_version


def _parse_mermaid_graph_content(
    mermaid_graph_content: list[str],
) -> dict[str, set[str]]:
    graph = defaultdict(set)

    for line in mermaid_graph_content:
        parts = line.strip().split("-->")
        parts = [part.strip() for part in parts]
        for i in range(len(parts) - 1):
            graph[parts[i]].add(parts[i + 1])

    return graph


def _generate_dependency_list_as_text(graph: dict[str, set[str]]) -> str:
    lines = []
    for src, dests in graph.items():
        for dest in sorted(dests):
            lines.append(f"{src} --> {dest}")
    return "\n".join(lines)
