from __future__ import annotations

from .backdoor import identify_candidate_confounders
from .dag import CausalGraph

E_CAUSAL_DAG_CYCLE = "E_CAUSAL_DAG_CYCLE"
E_TEMPORAL_INTEGRITY = "E_TEMPORAL_INTEGRITY"
E_BACKDOOR_UNADJUSTED = "E_BACKDOOR_UNADJUSTED"


class CausalValidationError(ValueError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}:{detail}"
        super().__init__(message)


def _build_adjacency(graph: CausalGraph) -> dict[str, tuple[str, ...]]:
    adjacency: dict[str, list[str]] = {node.node_id: [] for node in graph.nodes}
    for edge in graph.edges:
        adjacency[edge.src].append(edge.dst)
    return {node: tuple(sorted(children)) for node, children in adjacency.items()}


def validate_acyclic(graph: CausalGraph) -> None:
    adjacency = _build_adjacency(graph)
    visiting: set[str] = set()
    visited: set[str] = set()

    def dfs(node: str) -> None:
        if node in visiting:
            raise CausalValidationError(E_CAUSAL_DAG_CYCLE)
        if node in visited:
            return
        visiting.add(node)
        for neighbor in adjacency.get(node, ()):
            dfs(neighbor)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(adjacency.keys()):
        if node not in visited:
            dfs(node)


def validate_temporal_integrity(graph: CausalGraph) -> None:
    time_index = {node.node_id: node.time_index for node in graph.nodes}
    for edge in graph.edges:
        src_time = time_index[edge.src]
        dst_time = time_index[edge.dst]
        if src_time > dst_time:
            raise CausalValidationError(
                E_TEMPORAL_INTEGRITY,
                detail=f"{edge.src}->{edge.dst}",
            )


def validate_adjustment_set_contains_candidates(
    graph: CausalGraph,
    *,
    fail_closed: bool = True,
) -> tuple[str, ...]:
    candidates = identify_candidate_confounders(graph, graph.treatment, graph.outcome)
    adjustment_set = set(graph.adjustment_set)
    missing = sorted([node for node in candidates if node not in adjustment_set])
    if missing and fail_closed:
        raise CausalValidationError(E_BACKDOOR_UNADJUSTED, detail=",".join(missing))
    return tuple(missing)
