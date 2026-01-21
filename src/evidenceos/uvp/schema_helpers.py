from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from evidenceos.common.schema_validate import validate_json

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "uvp"


def schema_path(schema_name: str) -> Path:
    path = SCHEMA_DIR / schema_name
    if not path.is_file():
        raise FileNotFoundError(f"Schema not found: {path}")
    return path


def validate_safety_property(instance: Mapping[str, Any]) -> None:
    validate_json(instance, schema_path("safety_property.schema.json"))


def validate_adversarial_hypothesis(instance: Mapping[str, Any]) -> None:
    validate_json(instance, schema_path("adversarial_hypothesis.schema.json"))


__all__ = ["schema_path", "validate_adversarial_hypothesis", "validate_safety_property"]
