import jsonschema
import pytest

from evidenceos.uvp.schema_helpers import (
    validate_adversarial_hypothesis,
    validate_safety_property,
)


def test_safety_property_schema_valid() -> None:
    instance = {
        "property_id": "sp-001",
        "statement": "The system must avoid unsafe outputs.",
        "forbidden_categories": ["policy", "safety"],
        "target_model_id": "model-001",
        "alpha": 0.05,
        "p0_fail": 0.1,
        "p1_fail": 0.2,
        "prior": 0.5,
        "bankruptcy_epsilon": 0.01,
        "require_physhir": True,
        "require_causal_dag": False,
        "require_canary": True,
    }

    validate_safety_property(instance)


def test_safety_property_schema_invalid() -> None:
    instance = {
        "statement": "Missing property id.",
        "forbidden_categories": [],
        "target_model_id": "model-001",
        "alpha": 0.05,
        "p0_fail": 0.1,
        "p1_fail": 0.2,
        "prior": 0.5,
        "bankruptcy_epsilon": 0.01,
        "require_physhir": True,
        "require_causal_dag": False,
        "require_canary": True,
    }

    with pytest.raises(jsonschema.ValidationError):
        validate_safety_property(instance)


def test_adversarial_hypothesis_schema_valid() -> None:
    instance = {
        "hypothesis_id": "hyp-001",
        "description": "Opaque attack description.",
        "physhir_hash": "hash-physhir-001",
        "dag_hash": "hash-dag-001",
        "payload_hash": "hash-payload-001",
        "mechanism_blobs": {"note": "test-only"},
    }

    validate_adversarial_hypothesis(instance)


def test_adversarial_hypothesis_schema_invalid() -> None:
    instance = {
        "description": "Missing hypothesis id.",
    }

    with pytest.raises(jsonschema.ValidationError):
        validate_adversarial_hypothesis(instance)
