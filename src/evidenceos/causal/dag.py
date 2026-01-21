from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CausalNode:
    node_id: str
    time_index: int


@dataclass(frozen=True)
class CausalEdge:
    src: str
    dst: str


@dataclass(frozen=True)
class CausalGraph:
    nodes: tuple[CausalNode, ...]
    edges: tuple[CausalEdge, ...]
    treatment: str
    outcome: str
    adjustment_set: tuple[str, ...] = ()

    def node_ids(self) -> tuple[str, ...]:
        return tuple(node.node_id for node in self.nodes)


class CausalGraphParseError(ValueError):
    pass


def parse_causal_graph(data: Mapping[str, Any]) -> CausalGraph:
    nodes_raw = data.get("nodes")
    if not isinstance(nodes_raw, list):
        raise CausalGraphParseError("nodes must be a sequence")

    nodes: list[CausalNode] = []
    node_ids: list[str] = []
    for node in nodes_raw:
        if not isinstance(node, Mapping):
            raise CausalGraphParseError("node must be an object")
        node_id = node.get("id")
        time_index = node.get("time_index")
        if not isinstance(node_id, str):
            raise CausalGraphParseError("node id must be a string")
        if not isinstance(time_index, int):
            raise CausalGraphParseError("node time_index must be an int")
        nodes.append(CausalNode(node_id=node_id, time_index=time_index))
        node_ids.append(node_id)

    if len(set(node_ids)) != len(node_ids):
        raise CausalGraphParseError("duplicate node ids")

    edges_raw = data.get("edges")
    if not isinstance(edges_raw, list):
        raise CausalGraphParseError("edges must be a sequence")

    node_id_set = set(node_ids)
    edges: list[CausalEdge] = []
    for edge in edges_raw:
        if not isinstance(edge, Mapping):
            raise CausalGraphParseError("edge must be an object")
        src = edge.get("src")
        dst = edge.get("dst")
        if not isinstance(src, str) or not isinstance(dst, str):
            raise CausalGraphParseError("edge src/dst must be strings")
        if src not in node_id_set or dst not in node_id_set:
            raise CausalGraphParseError("edge references unknown node")
        edges.append(CausalEdge(src=src, dst=dst))

    treatment = data.get("treatment")
    outcome = data.get("outcome")
    if not isinstance(treatment, str) or not isinstance(outcome, str):
        raise CausalGraphParseError("treatment/outcome must be strings")

    adjustment_raw = data.get("adjustment_set", [])
    if not isinstance(adjustment_raw, list):
        raise CausalGraphParseError("adjustment_set must be a sequence")

    adjustment_set: list[str] = []
    for node_id in adjustment_raw:
        if not isinstance(node_id, str):
            raise CausalGraphParseError("adjustment_set entries must be strings")
        adjustment_set.append(node_id)

    return CausalGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        treatment=treatment,
        outcome=outcome,
        adjustment_set=tuple(adjustment_set),
    )
