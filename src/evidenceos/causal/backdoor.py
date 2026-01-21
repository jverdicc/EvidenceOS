from __future__ import annotations

from .dag import CausalGraph


def _reverse_adjacency(graph: CausalGraph) -> dict[str, tuple[str, ...]]:
    reverse: dict[str, list[str]] = {node.node_id: [] for node in graph.nodes}
    for edge in graph.edges:
        reverse[edge.dst].append(edge.src)
    return {node: tuple(sorted(parents)) for node, parents in reverse.items()}


def _collect_ancestors(reverse_adjacency: dict[str, tuple[str, ...]], target: str) -> set[str]:
    ancestors: set[str] = set()
    stack: list[str] = list(reverse_adjacency.get(target, ()))
    while stack:
        current = stack.pop()
        if current in ancestors:
            continue
        ancestors.add(current)
        stack.extend(reverse_adjacency.get(current, ()))
    return ancestors


def identify_candidate_confounders(
    graph: CausalGraph,
    treatment: str,
    outcome: str,
) -> tuple[str, ...]:
    reverse = _reverse_adjacency(graph)
    treatment_ancestors = _collect_ancestors(reverse, treatment)
    outcome_ancestors = _collect_ancestors(reverse, outcome)
    candidates = (treatment_ancestors & outcome_ancestors) - {treatment, outcome}
    return tuple(sorted(candidates))
