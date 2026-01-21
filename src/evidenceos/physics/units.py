from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum


class SIBase(str, Enum):
    M = "M"
    L = "L"
    T = "T"
    I = "I"  # noqa: E741
    THETA = "THETA"
    N = "N"
    J = "J"


SI_BASES: tuple[SIBase, ...] = (
    SIBase.M,
    SIBase.L,
    SIBase.T,
    SIBase.I,
    SIBase.THETA,
    SIBase.N,
    SIBase.J,
)


class DimensionError(Exception):
    def __init__(self, code: str, message: str, path: str | None = None) -> None:
        self.code = code
        self.message = message
        self.path = path
        super().__init__(self.__str__())

    def __str__(self) -> str:
        if self.path:
            return f"{self.code}: {self.message} ({self.path})"
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class Dimension:
    exponents: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.exponents) != len(SI_BASES):
            raise ValueError("Dimension must include all SI base exponents")

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, int]) -> Dimension:
        exponents: list[int] = []
        for base in SI_BASES:
            value = mapping.get(base.value, 0)
            if not isinstance(value, int):
                raise DimensionError(
                    "E_DIMENSIONAL_INVALID",
                    f"Exponent for {base.value} must be int",
                    path=base.value,
                )
            exponents.append(value)
        return cls(tuple(exponents))

    @property
    def mapping(self) -> dict[str, int]:
        return {base.value: exp for base, exp in zip(SI_BASES, self.exponents, strict=True)}

    def is_dimensionless(self) -> bool:
        return all(exp == 0 for exp in self.exponents)

    def add_dims(self, other: Dimension) -> Dimension:
        return Dimension(
            tuple(a + b for a, b in zip(self.exponents, other.exponents, strict=True))
        )

    def sub_dims(self, other: Dimension) -> Dimension:
        return Dimension(
            tuple(a - b for a, b in zip(self.exponents, other.exponents, strict=True))
        )

    def scale_dims(self, power: int) -> Dimension:
        if not isinstance(power, int):
            raise DimensionError(
                "E_DIMENSIONAL_INVALID",
                "Power must be an integer",
            )
        return Dimension(tuple(exp * power for exp in self.exponents))


DIMENSIONLESS = Dimension(tuple(0 for _ in SI_BASES))


def require_same_dimensions(
    left: Dimension,
    right: Dimension,
    *,
    path: str | None = None,
) -> Dimension:
    if left != right:
        raise DimensionError(
            "E_DIMENSIONAL_INVALID",
            "Dimensions must match for addition/subtraction",
            path=path,
        )
    return left


def require_dimensionless(
    dimension: Dimension,
    *,
    op: str,
    path: str | None = None,
) -> Dimension:
    if not dimension.is_dimensionless():
        raise DimensionError(
            "E_DIMENSIONAL_INVALID",
            f"{op} requires a dimensionless input",
            path=path,
        )
    return DIMENSIONLESS


class UnitRegistry:
    def __init__(self) -> None:
        self._registry: dict[str, Dimension] = {}

    def register_variable(self, name: str, dimension: Dimension) -> None:
        self._registry[name] = dimension

    def get_dimension(self, name: str) -> Dimension:
        try:
            return self._registry[name]
        except KeyError as exc:
            raise DimensionError(
                "E_MISSING_UNITS",
                f"Variable '{name}' is not registered",
                path=name,
            ) from exc


_BASE_UNIT_MAP: dict[str, Dimension] = {
    "m": Dimension.from_mapping({"L": 1}),
    "kg": Dimension.from_mapping({"M": 1}),
    "s": Dimension.from_mapping({"T": 1}),
    "A": Dimension.from_mapping({"I": 1}),
    "K": Dimension.from_mapping({"THETA": 1}),
    "mol": Dimension.from_mapping({"N": 1}),
    "cd": Dimension.from_mapping({"J": 1}),
}


def parse_dimension(value: Mapping[str, int] | str | None) -> Dimension:
    if value is None:
        raise DimensionError("E_MISSING_UNITS", "Units are required")
    if isinstance(value, str):
        return _parse_unit_string(value)
    return Dimension.from_mapping(value)


def _parse_unit_string(unit: str) -> Dimension:
    cleaned = unit.strip()
    if cleaned == "":
        raise DimensionError("E_MISSING_UNITS", "Units are required")
    if cleaned == "1":
        return DIMENSIONLESS

    tokens = _tokenize_unit_string(cleaned)
    dimension = DIMENSIONLESS
    operation = "*"
    for token in tokens:
        if token in {"*", "/"}:
            operation = token
            continue
        token_dim = _parse_unit_token(token)
        if operation == "*":
            dimension = dimension.add_dims(token_dim)
        else:
            dimension = dimension.sub_dims(token_dim)
    return dimension


def _tokenize_unit_string(unit: str) -> list[str]:
    tokens: list[str] = []
    buffer: list[str] = []
    for char in unit:
        if char in {"*", "/"}:
            if not buffer:
                raise DimensionError("E_DIMENSIONAL_INVALID", "Malformed unit string")
            tokens.append("".join(buffer))
            buffer = []
            tokens.append(char)
        else:
            buffer.append(char)
    if not buffer:
        raise DimensionError("E_DIMENSIONAL_INVALID", "Malformed unit string")
    tokens.append("".join(buffer))
    return tokens


def _parse_unit_token(token: str) -> Dimension:
    token = token.strip()
    if token == "":
        raise DimensionError("E_DIMENSIONAL_INVALID", "Empty unit token")
    if "^" in token:
        base, power_text = token.split("^", 1)
        if power_text == "":
            raise DimensionError("E_DIMENSIONAL_INVALID", "Missing exponent")
        try:
            power = int(power_text)
        except ValueError as exc:
            raise DimensionError(
                "E_DIMENSIONAL_INVALID",
                "Exponent must be integer",
            ) from exc
    else:
        base = token
        power = 1

    if base not in _BASE_UNIT_MAP:
        raise DimensionError(
            "E_UNKNOWN_UNIT",
            f"Unknown unit '{base}'",
            path=base,
        )

    return _BASE_UNIT_MAP[base].scale_dims(power)


def add_dimensions(left: Dimension, right: Dimension, *, path: str | None = None) -> Dimension:
    return require_same_dimensions(left, right, path=path)


def sub_dimensions(left: Dimension, right: Dimension, *, path: str | None = None) -> Dimension:
    return require_same_dimensions(left, right, path=path)


def mul_dimensions(left: Dimension, right: Dimension) -> Dimension:
    return left.add_dims(right)


def div_dimensions(left: Dimension, right: Dimension) -> Dimension:
    return left.sub_dims(right)


def pow_dimension(dimension: Dimension, power: int) -> Dimension:
    return dimension.scale_dims(power)


def exp_dimension(dimension: Dimension, *, path: str | None = None) -> Dimension:
    return require_dimensionless(dimension, op="exp", path=path)


def log_dimension(dimension: Dimension, *, path: str | None = None) -> Dimension:
    return require_dimensionless(dimension, op="log", path=path)


def sin_dimension(dimension: Dimension, *, path: str | None = None) -> Dimension:
    return require_dimensionless(dimension, op="sin", path=path)


__all__ = [
    "DIMENSIONLESS",
    "SI_BASES",
    "Dimension",
    "DimensionError",
    "SIBase",
    "UnitRegistry",
    "add_dimensions",
    "div_dimensions",
    "exp_dimension",
    "log_dimension",
    "mul_dimensions",
    "parse_dimension",
    "pow_dimension",
    "sin_dimension",
    "sub_dimensions",
]
