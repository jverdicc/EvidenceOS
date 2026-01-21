from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class Expr:
    """Base class for PhysHIR expressions."""


@dataclass(frozen=True)
class Var(Expr):
    name: str


@dataclass(frozen=True)
class Const(Expr):
    value: float
    units: str | None = None


@dataclass(frozen=True)
class Add(Expr):
    lhs: Expr
    rhs: Expr


@dataclass(frozen=True)
class Sub(Expr):
    lhs: Expr
    rhs: Expr


@dataclass(frozen=True)
class Mul(Expr):
    lhs: Expr
    rhs: Expr


@dataclass(frozen=True)
class Div(Expr):
    lhs: Expr
    rhs: Expr


@dataclass(frozen=True)
class Pow(Expr):
    base: Expr
    exponent: int


@dataclass(frozen=True)
class Exp(Expr):
    arg: Expr


@dataclass(frozen=True)
class Log(Expr):
    arg: Expr


@dataclass(frozen=True)
class Sin(Expr):
    arg: Expr


@dataclass(frozen=True)
class Cos(Expr):
    arg: Expr


@dataclass(frozen=True)
class Clamp(Expr):
    arg: Expr
    min: float
    max: float


def _expect_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"Expected mapping for {label}.")
    return value


def parse_expr(data: Mapping[str, Any]) -> Expr:
    node_type = data.get("type")
    if node_type == "Var":
        return Var(name=str(data["name"]))
    if node_type == "Const":
        units = data.get("units")
        return Const(value=float(data["value"]), units=str(units) if units is not None else None)
    if node_type == "Add":
        lhs = parse_expr(_expect_mapping(data["lhs"], "Add.lhs"))
        rhs = parse_expr(_expect_mapping(data["rhs"], "Add.rhs"))
        return Add(lhs=lhs, rhs=rhs)
    if node_type == "Sub":
        lhs = parse_expr(_expect_mapping(data["lhs"], "Sub.lhs"))
        rhs = parse_expr(_expect_mapping(data["rhs"], "Sub.rhs"))
        return Sub(lhs=lhs, rhs=rhs)
    if node_type == "Mul":
        lhs = parse_expr(_expect_mapping(data["lhs"], "Mul.lhs"))
        rhs = parse_expr(_expect_mapping(data["rhs"], "Mul.rhs"))
        return Mul(lhs=lhs, rhs=rhs)
    if node_type == "Div":
        lhs = parse_expr(_expect_mapping(data["lhs"], "Div.lhs"))
        rhs = parse_expr(_expect_mapping(data["rhs"], "Div.rhs"))
        return Div(lhs=lhs, rhs=rhs)
    if node_type == "Pow":
        base = parse_expr(_expect_mapping(data["base"], "Pow.base"))
        exponent = int(data["exponent"])
        return Pow(base=base, exponent=exponent)
    if node_type == "Exp":
        arg = parse_expr(_expect_mapping(data["arg"], "Exp.arg"))
        return Exp(arg=arg)
    if node_type == "Log":
        arg = parse_expr(_expect_mapping(data["arg"], "Log.arg"))
        return Log(arg=arg)
    if node_type == "Sin":
        arg = parse_expr(_expect_mapping(data["arg"], "Sin.arg"))
        return Sin(arg=arg)
    if node_type == "Cos":
        arg = parse_expr(_expect_mapping(data["arg"], "Cos.arg"))
        return Cos(arg=arg)
    if node_type == "Clamp":
        arg = parse_expr(_expect_mapping(data["arg"], "Clamp.arg"))
        return Clamp(arg=arg, min=float(data["min"]), max=float(data["max"]))
    raise ValueError(f"Unknown PhysHIR node type '{node_type}'.")


__all__ = [
    "Add",
    "Clamp",
    "Const",
    "Cos",
    "Div",
    "Exp",
    "Expr",
    "Log",
    "Mul",
    "Pow",
    "Sin",
    "Sub",
    "Var",
    "parse_expr",
]
