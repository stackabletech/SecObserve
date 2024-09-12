import logging
from collections import defaultdict

from application.import_observations.parsers.cyclone_dx.types import Component, Metadata

logger = logging.getLogger("secobserve.import_observations.cyclone_dx.dependencies")


def get_component_dependencies(
    data: dict,
    components: dict[str, Component],
    component: Component,
    metadata: Metadata,
) -> tuple[str, list[dict]]:
    component_dependencies: list[dict[str, str | list[str]]] = []
    _filter_component_dependencies(
        component.bom_ref,
        data.get("dependencies", []),
        component_dependencies,
    )
    observation_component_dependencies = ""
    translated_component_dependencies = []
    if component_dependencies:
        translated_component_dependencies = _translate_component_dependencies(
            component_dependencies, components
        )

        observation_component_dependencies = generate_dependency_list_as_text(
            _get_dependencies(
                component.bom_ref,
                component_dependencies,
                components,
                metadata,
            )
        )

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


def _get_dependencies(
    component_bom_ref: str,
    component_dependencies: list[dict],
    components: dict[str, Component],
    metadata: Metadata,
) -> dict[str, set[str]]:
    roots = _get_roots(component_dependencies)

    dependencies: list[str] = []
    cache: dict[(str, str), list[str]] = {}
    try:
        for root in roots:
            sub_dependencies = _get_dependencies_recursive(
                cache,
                root,
                _translate_component(root, components),
                root,
                component_bom_ref,
                component_dependencies,
                components,
            )
            dependencies += sub_dependencies

    except RecursionError as e:
        logger.warning(
            "%s:%s -> %s", metadata.container_name, metadata.container_tag, str(e)
        )
        return {}

    return_dependencies = []
    for dependency in dependencies:
        if (
            dependency
            and dependency.endswith(_translate_component(component_bom_ref, components))
            or dependency.startswith("Circular dependency for")
        ):
            return_dependencies.append(dependency)

    edges = parse_mermaid_graph_content(sorted(return_dependencies))
    graph = build_graph(edges)
    reduced_graph = remove_redundant_paths(graph)

    return reduced_graph


def _get_dependencies_recursive(
    cache: dict[(str, str), list[str]],
    root: str,
    translated_initial_dependency: str,
    initial_dependency: str,
    component_bom_ref: str,
    component_dependencies: list[dict],
    components: dict[str, Component],
) -> list[str]:
    if (root, component_bom_ref) in cache:
        return cache[(root, component_bom_ref)]

    dependencies = []
    for dependency in component_dependencies:
        ref = dependency.get("ref")
        if ref == root:
            for dependant in dependency.get("dependsOn", []):
                translated_dependant = _translate_component(dependant, components)
                if dependant in initial_dependency:
                    return [f"Circular dependency for {translated_dependant}"]

                new_translated_dependency = (
                    f"{translated_initial_dependency} --> {translated_dependant}"
                )
                new_dependency = f"{initial_dependency} --> {dependant}"
                if dependant == component_bom_ref:
                    dependencies.append(new_translated_dependency)
                else:
                    new_dependencies = _get_dependencies_recursive(
                        cache,
                        dependant,
                        new_translated_dependency,
                        new_dependency,
                        component_bom_ref,
                        component_dependencies,
                        components,
                    )
                    if new_dependencies not in dependencies:
                        dependencies += new_dependencies

    cache[(root, component_bom_ref)] = dependencies
    return dependencies


def _get_roots(
    translated_component_dependencies: list[dict],
) -> list[str]:
    roots = []
    for dependency in translated_component_dependencies:
        ref = dependency.get("ref")
        if not ref:
            continue
        if not any(
            ref in d.get("dependsOn", []) for d in translated_component_dependencies
        ):
            roots.append(ref)

    return roots


def parse_mermaid_graph_content(
    mermaid_graph_content: list[str],
) -> list[tuple[str, str]]:
    edges = []
    for line in mermaid_graph_content:
        parts = line.strip().split("-->")
        parts = [part.strip() for part in parts]
        for i in range(len(parts) - 1):
            edges.append((parts[i], parts[i + 1]))
    return edges


def build_graph(edges: list[tuple[str, str]]) -> dict[str, set[str]]:
    graph = defaultdict(set)
    for src, dest in edges:
        graph[src].add(dest)
    return graph


def remove_redundant_paths(graph: dict[str, set[str]]) -> dict[str, set[str]]:
    # Perform a DFS to remove redundant paths
    def dfs(
        node: str,
        visited: dict[str, set[str]],
    ) -> set[str]:
        if node in visited:
            return visited[node]
        visited[node] = set()
        for neighbor in graph[node]:
            visited[node].add(neighbor)
            visited[node].update(dfs(neighbor, visited))
        return visited[node]

    visited: dict[str, set[str]] = {}
    for node in list(graph.keys()):
        if node not in visited:
            dfs(node, visited)

    reduced_graph = defaultdict(set)
    for node, neighbors in graph.items():
        for neighbor in neighbors:
            if not any(
                neighbor in visited[other] for other in neighbors if other != neighbor
            ):
                reduced_graph[node].add(neighbor)
    return reduced_graph


def generate_dependency_list_as_text(graph: dict[str, set[str]]) -> str:
    lines = []
    for src, dests in graph.items():
        for dest in dests:
            lines.append(f"{src} --> {dest}")
    return "\n".join(lines)
