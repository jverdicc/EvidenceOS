from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

from evidenceos.physics.hir_ast import (
    Add,
    Clamp,
    Const,
    Cos,
    Div,
    Exp,
    Expr,
    Log,
    Mul,
    Pow,
    Sin,
    Sub,
    Var,
)

if TYPE_CHECKING:
    from evidenceos.physics.physhir import PhysHIR

E_DIMENSIONAL_INVALID = "E_DIMENSIONAL_INVALID"
E_DIMENSIONLESS_REQUIRED = "E_DIMENSIONLESS_REQUIRED"
E_DIMENSIONAL_TARGET_MISMATCH = "E_DIMENSIONAL_TARGET_MISMATCH"
E_VARIABLE_UNKNOWN = "E_VARIABLE_UNKNOWN"
E_UNITS_INVALID = "E_UNITS_INVALID"

_UNIT_FACTOR_RE = re.compile(r"^([A-Za-z]+)(?:\^(-?\d+))?$")


class DimensionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class Dimension:
    exponents: tuple[tuple[str, int], ...]

    @classmethod
    def dimensionless(cls) -> Dimension:
        return cls(exponents=())

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, int]) -> Dimension:
        filtered = {unit: exp for unit, exp in mapping.items() if exp != 0}
        return cls(exponents=tuple(sorted(filtered.items())))

    def to_mapping(self) -> dict[str, int]:
        return dict(self.exponents)

    def multiply(self, other: Dimension) -> Dimension:
        combined = self.to_mapping()
        for unit, exp in other.exponents:
            combined[unit] = combined.get(unit, 0) + exp
        return Dimension.from_mapping(combined)

    def divide(self, other: Dimension) -> Dimension:
        combined = self.to_mapping()
        for unit, exp in other.exponents:
            combined[unit] = combined.get(unit, 0) - exp
        return Dimension.from_mapping(combined)

    def power(self, exponent: int) -> Dimension:
        powered = {unit: exp * exponent for unit, exp in self.exponents}
        return Dimension.from_mapping(powered)

    def is_dimensionless(self) -> bool:
        return not self.exponents


def parse_units(units: str | None) -> Dimension:
    if units is None:
        return Dimension.dimensionless()
    normalized = units.replace(" ", "")
    if normalized == "" or normalized == "1":
        return Dimension.dimensionless()

    mapping: dict[str, int] = {}
    parts = normalized.split("/")
    for index, part in enumerate(parts):
        if part == "":
            raise DimensionError(E_UNITS_INVALID, "Invalid units string.")
        sign = 1 if index == 0 else -1
        for factor in part.split("*"):
            if factor == "":
                raise DimensionError(E_UNITS_INVALID, "Invalid units string.")
            match = _UNIT_FACTOR_RE.match(factor)
            if not match:
                raise DimensionError(E_UNITS_INVALID, f"Invalid unit factor '{factor}'.")
            unit, exp_text = match.groups()
            exponent = int(exp_text) if exp_text is not None else 1
            mapping[unit] = mapping.get(unit, 0) + sign * exponent
    return Dimension.from_mapping(mapping)


def infer_dimension(node: Expr, registry: Mapping[str, Dimension]) -> Dimension:
    if isinstance(node, Var):
        if node.name not in registry:
            raise DimensionError(E_VARIABLE_UNKNOWN, f"Unknown variable '{node.name}'.")
        return registry[node.name]
    if isinstance(node, Const):
        return parse_units(node.units)
    if isinstance(node, Add):
        lhs = infer_dimension(node.lhs, registry)
        rhs = infer_dimension(node.rhs, registry)
        if lhs != rhs:
            raise DimensionError(E_DIMENSIONAL_INVALID, "Add/Sub dimension mismatch.")
        return lhs
    if isinstance(node, Sub):
        lhs = infer_dimension(node.lhs, registry)
        rhs = infer_dimension(node.rhs, registry)
        if lhs != rhs:
            raise DimensionError(E_DIMENSIONAL_INVALID, "Add/Sub dimension mismatch.")
        return lhs
    if isinstance(node, Mul):
        return infer_dimension(node.lhs, registry).multiply(
            infer_dimension(node.rhs, registry)
        )
    if isinstance(node, Div):
        return infer_dimension(node.lhs, registry).divide(
            infer_dimension(node.rhs, registry)
        )
    if isinstance(node, Pow):
        base = infer_dimension(node.base, registry)
        return base.power(node.exponent)
    if isinstance(node, Exp):
        arg_dim = infer_dimension(node.arg, registry)
        if not arg_dim.is_dimensionless():
            raise DimensionError(
                E_DIMENSIONLESS_REQUIRED, "Exp/Log/Sin/Cos require dimensionless input."
            )
        return Dimension.dimensionless()
    if isinstance(node, Log):
        arg_dim = infer_dimension(node.arg, registry)
        if not arg_dim.is_dimensionless():
            raise DimensionError(
                E_DIMENSIONLESS_REQUIRED, "Exp/Log/Sin/Cos require dimensionless input."
            )
        return Dimension.dimensionless()
    if isinstance(node, Sin):
        arg_dim = infer_dimension(node.arg, registry)
        if not arg_dim.is_dimensionless():
            raise DimensionError(
                E_DIMENSIONLESS_REQUIRED, "Exp/Log/Sin/Cos require dimensionless input."
            )
        return Dimension.dimensionless()
    if isinstance(node, Cos):
        arg_dim = infer_dimension(node.arg, registry)
        if not arg_dim.is_dimensionless():
            raise DimensionError(
                E_DIMENSIONLESS_REQUIRED, "Exp/Log/Sin/Cos require dimensionless input."
            )
        return Dimension.dimensionless()
    if isinstance(node, Clamp):
        return infer_dimension(node.arg, registry)
    raise ValueError(f"Unknown PhysHIR node '{type(node).__name__}'.")


def validate_target_dimension(physhir: PhysHIR) -> Dimension:
    registry = {var.name: parse_units(var.units) for var in physhir.variables}
    expr_dim = infer_dimension(physhir.expression, registry)
    target_dim = parse_units(physhir.target.units)
    if expr_dim != target_dim:
        raise DimensionError(
            E_DIMENSIONAL_TARGET_MISMATCH,
            "Expression dimension does not match target dimension.",
        )
    return expr_dim


class Typechecker:
    def validate(self, physhir: PhysHIR) -> Dimension:
        return validate_target_dimension(physhir)


__all__ = [
    "Dimension",
    "DimensionError",
    "E_DIMENSIONAL_INVALID",
    "E_DIMENSIONAL_TARGET_MISMATCH",
    "E_DIMENSIONLESS_REQUIRED",
    "E_UNITS_INVALID",
    "E_VARIABLE_UNKNOWN",
    "Typechecker",
    "infer_dimension",
    "parse_units",
    "validate_target_dimension",
]
