from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from evidenceos.uvp.schema_helpers import (
    validate_adversarial_hypothesis,
    validate_safety_property,
)


@dataclass(frozen=True)
class SafetyProperty:
    property_id: str
    statement: str
    forbidden_categories: tuple[str, ...]
    target_model_id: str
    alpha: float
    p0_fail: float
    p1_fail: float
    prior: float
    bankruptcy_epsilon: float
    require_physhir: bool
    require_causal_dag: bool
    require_canary: bool

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SafetyProperty":
        validate_safety_property(data)
        return cls(
            property_id=str(data["property_id"]),
            statement=str(data["statement"]),
            forbidden_categories=tuple(
                str(category) for category in data["forbidden_categories"]
            ),
            target_model_id=str(data["target_model_id"]),
            alpha=float(data["alpha"]),
            p0_fail=float(data["p0_fail"]),
            p1_fail=float(data["p1_fail"]),
            prior=float(data["prior"]),
            bankruptcy_epsilon=float(data["bankruptcy_epsilon"]),
            require_physhir=bool(data["require_physhir"]),
            require_causal_dag=bool(data["require_causal_dag"]),
            require_canary=bool(data["require_canary"]),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "property_id": self.property_id,
            "statement": self.statement,
            "forbidden_categories": list(self.forbidden_categories),
            "target_model_id": self.target_model_id,
            "alpha": self.alpha,
            "p0_fail": self.p0_fail,
            "p1_fail": self.p1_fail,
            "prior": self.prior,
            "bankruptcy_epsilon": self.bankruptcy_epsilon,
            "require_physhir": self.require_physhir,
            "require_causal_dag": self.require_causal_dag,
            "require_canary": self.require_canary,
        }


@dataclass(frozen=True)
class AdversarialHypothesis:
    hypothesis_id: str
    description: str
    physhir_hash: str | None = None
    dag_hash: str | None = None
    payload_hash: str | None = None
    mechanism_blobs: dict[str, str] | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AdversarialHypothesis":
        validate_adversarial_hypothesis(data)
        mechanism_blobs = data.get("mechanism_blobs")
        normalized_blobs: dict[str, str] | None
        if mechanism_blobs is None:
            normalized_blobs = None
        else:
            normalized_blobs = {
                str(key): str(value) for key, value in dict(mechanism_blobs).items()
            }
        return cls(
            hypothesis_id=str(data["hypothesis_id"]),
            description=str(data["description"]),
            physhir_hash=_optional_str(data, "physhir_hash"),
            dag_hash=_optional_str(data, "dag_hash"),
            payload_hash=_optional_str(data, "payload_hash"),
            mechanism_blobs=normalized_blobs,
        )

    def to_mapping(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "hypothesis_id": self.hypothesis_id,
            "description": self.description,
        }
        if self.physhir_hash is not None:
            payload["physhir_hash"] = self.physhir_hash
        if self.dag_hash is not None:
            payload["dag_hash"] = self.dag_hash
        if self.payload_hash is not None:
            payload["payload_hash"] = self.payload_hash
        if self.mechanism_blobs is not None:
            payload["mechanism_blobs"] = dict(self.mechanism_blobs)
        return payload


def _optional_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    return str(value)


__all__ = ["AdversarialHypothesis", "SafetyProperty"]
