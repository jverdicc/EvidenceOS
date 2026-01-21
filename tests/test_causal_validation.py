import pytest

from evidenceos.causal.backdoor import identify_candidate_confounders
from evidenceos.causal.dag import parse_causal_graph
from evidenceos.causal.validate import (
    CausalValidationError,
    E_BACKDOOR_UNADJUSTED,
    E_CAUSAL_DAG_CYCLE,
    E_TEMPORAL_INTEGRITY,
    validate_acyclic,
    validate_adjustment_set_contains_candidates,
    validate_temporal_integrity,
)


def test_cycle_detected() -> None:
    graph = parse_causal_graph(
        {
            "nodes": [
                {"id": "X", "time_index": 0},
                {"id": "Y", "time_index": 0},
            ],
            "edges": [
                {"src": "X", "dst": "Y"},
                {"src": "Y", "dst": "X"},
            ],
            "treatment": "X",
            "outcome": "Y",
            "adjustment_set": [],
        }
    )

    with pytest.raises(CausalValidationError) as excinfo:
        validate_acyclic(graph)

    assert excinfo.value.code == E_CAUSAL_DAG_CYCLE


def test_temporal_integrity_rejects_future_to_past_edge() -> None:
    graph = parse_causal_graph(
        {
            "nodes": [
                {"id": "X", "time_index": 1},
                {"id": "Y", "time_index": 0},
            ],
            "edges": [
                {"src": "X", "dst": "Y"},
            ],
            "treatment": "X",
            "outcome": "Y",
            "adjustment_set": [],
        }
    )

    with pytest.raises(CausalValidationError) as excinfo:
        validate_temporal_integrity(graph)

    assert excinfo.value.code == E_TEMPORAL_INTEGRITY


def test_confounder_detection_flags_common_causes() -> None:
    graph = parse_causal_graph(
        {
            "nodes": [
                {"id": "X", "time_index": 0},
                {"id": "Y", "time_index": 0},
                {"id": "Z", "time_index": 0},
            ],
            "edges": [
                {"src": "Z", "dst": "X"},
                {"src": "Z", "dst": "Y"},
            ],
            "treatment": "X",
            "outcome": "Y",
            "adjustment_set": ["Z"],
        }
    )

    assert identify_candidate_confounders(graph, "X", "Y") == ("Z",)


def test_missing_adjustment_set_fails_closed() -> None:
    graph = parse_causal_graph(
        {
            "nodes": [
                {"id": "X", "time_index": 0},
                {"id": "Y", "time_index": 0},
                {"id": "Z", "time_index": 0},
            ],
            "edges": [
                {"src": "Z", "dst": "X"},
                {"src": "Z", "dst": "Y"},
            ],
            "treatment": "X",
            "outcome": "Y",
            "adjustment_set": [],
        }
    )

    with pytest.raises(CausalValidationError) as excinfo:
        validate_adjustment_set_contains_candidates(graph)

    assert excinfo.value.code == E_BACKDOOR_UNADJUSTED
