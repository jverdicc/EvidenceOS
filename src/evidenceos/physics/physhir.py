from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidenceos.common.schema_validate import validate_json
from evidenceos.physics.hir_ast import Expr, parse_expr


@dataclass(frozen=True)
class TargetSpec:
    name: str
    units: str


@dataclass(frozen=True)
class VariableSpec:
    name: str
    units: str


@dataclass(frozen=True)
class PhysHIR:
    target: TargetSpec
    variables: tuple[VariableSpec, ...]
    expression: Expr


class PhysHIRCompiler:
    def __init__(self, schema_path: Path | None = None) -> None:
        self._schema_path = schema_path or _default_schema_path()

    def load(self, instance: Mapping[str, Any]) -> PhysHIR:
        validate_json(instance, self._schema_path)
        target_data = instance["target"]
        target = TargetSpec(name=str(target_data["name"]), units=str(target_data["units"]))
        variables = tuple(
            VariableSpec(name=str(var["name"]), units=str(var["units"]))
            for var in instance["variables"]
        )
        expression = parse_expr(instance["expression"])
        return PhysHIR(target=target, variables=variables, expression=expression)


def _default_schema_path() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas" / "physics" / "physhir.schema.json"


__all__ = ["PhysHIR", "PhysHIRCompiler", "TargetSpec", "VariableSpec"]
