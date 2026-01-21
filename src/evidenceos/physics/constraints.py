from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass


class ConstraintViolation(RuntimeError):
    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        message = code if detail is None else f"{code}:{detail}"
        super().__init__(message)


@dataclass(frozen=True)
class PinnedPrimary:
    name: str
    units: str
    value: float
    locked: bool = True


@dataclass(frozen=True)
class RangeConstraint:
    var: str
    min: float | None
    max: float | None
    units: str


@dataclass(frozen=True)
class ConservationConstraint:
    kind: str
    inputs: list[str]
    outputs: list[str]
    tolerance: float
    units: str


def _ensure_str(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be str")
    return value


def _ensure_bool(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{context} must be bool")
    return value


def _ensure_float(value: object, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{context} must be float")
    return float(value)


def _ensure_str_list(value: object, context: str) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise TypeError(f"{context} must be list[str]")
    items: list[str] = []
    for entry in value:
        items.append(_ensure_str(entry, context))
    if not items:
        raise TypeError(f"{context} must be non-empty list[str]")
    return items


def _coerce_pinned_primary(item: PinnedPrimary | Mapping[str, object]) -> PinnedPrimary:
    if isinstance(item, PinnedPrimary):
        return item
    locked_value = item.get("locked", True)
    return PinnedPrimary(
        name=_ensure_str(item["name"], "pinned_primary.name"),
        units=_ensure_str(item["units"], "pinned_primary.units"),
        value=_ensure_float(item["value"], "pinned_primary.value"),
        locked=_ensure_bool(locked_value, "pinned_primary.locked"),
    )


def _coerce_range_constraint(item: RangeConstraint | Mapping[str, object]) -> RangeConstraint:
    if isinstance(item, RangeConstraint):
        return item
    min_value = item.get("min")
    max_value = item.get("max")
    return RangeConstraint(
        var=_ensure_str(item["var"], "range.var"),
        min=None if min_value is None else _ensure_float(min_value, "range.min"),
        max=None if max_value is None else _ensure_float(max_value, "range.max"),
        units=_ensure_str(item["units"], "range.units"),
    )


def _coerce_conservation_constraint(
    item: ConservationConstraint | Mapping[str, object],
) -> ConservationConstraint:
    if isinstance(item, ConservationConstraint):
        return item
    return ConservationConstraint(
        kind=_ensure_str(item["kind"], "conservation.kind"),
        inputs=_ensure_str_list(item["inputs"], "conservation.inputs"),
        outputs=_ensure_str_list(item["outputs"], "conservation.outputs"),
        tolerance=_ensure_float(item["tolerance"], "conservation.tolerance"),
        units=_ensure_str(item["units"], "conservation.units"),
    )


def _iter_records(
    data_point: Mapping[str, float] | Sequence[Mapping[str, float]],
) -> Iterable[Mapping[str, float]]:
    if isinstance(data_point, Mapping):
        yield data_point
        return
    if isinstance(data_point, Sequence) and not isinstance(data_point, (str, bytes)):
        for record in data_point:
            if not isinstance(record, Mapping):
                raise TypeError("data_point batch must contain mappings")
            yield record
        return
    raise TypeError("data_point must be a mapping or sequence of mappings")


def _get_record_value(record: Mapping[str, float], key: str, code: str) -> float:
    if key not in record:
        raise ConstraintViolation(code, f"missing:{key}")
    value = record[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConstraintViolation(code, f"non_numeric:{key}")
    return float(value)


def validate_pinned_primaries(
    physhir: Mapping[str, float],
    constraints: Sequence[PinnedPrimary | Mapping[str, object]],
) -> None:
    for item in constraints:
        pinned = _coerce_pinned_primary(item)
        if not pinned.locked:
            continue
        if pinned.name not in physhir:
            continue
        value = physhir[pinned.name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConstraintViolation("E_PINNED_PRIMARY_VIOLATION", f"non_numeric:{pinned.name}")
        if float(value) != pinned.value:
            raise ConstraintViolation("E_PINNED_PRIMARY_VIOLATION", pinned.name)


def validate_ranges(
    data_point: Mapping[str, float] | Sequence[Mapping[str, float]],
    constraints: Sequence[RangeConstraint | Mapping[str, object]],
) -> None:
    for record in _iter_records(data_point):
        for item in constraints:
            constraint = _coerce_range_constraint(item)
            value = _get_record_value(record, constraint.var, "E_RANGE_VIOLATION")
            if constraint.min is not None and value < constraint.min:
                raise ConstraintViolation("E_RANGE_VIOLATION", f"{constraint.var}<min")
            if constraint.max is not None and value > constraint.max:
                raise ConstraintViolation("E_RANGE_VIOLATION", f"{constraint.var}>max")


def validate_conservation(
    data_point: Mapping[str, float] | Sequence[Mapping[str, float]],
    constraints: Sequence[ConservationConstraint | Mapping[str, object]],
) -> None:
    for record in _iter_records(data_point):
        for item in constraints:
            constraint = _coerce_conservation_constraint(item)
            if constraint.tolerance < 0:
                raise ConstraintViolation("E_CONSERVATION_VIOLATION", "negative_tolerance")
            input_total = sum(
                _get_record_value(record, name, "E_CONSERVATION_VIOLATION")
                for name in constraint.inputs
            )
            output_total = sum(
                _get_record_value(record, name, "E_CONSERVATION_VIOLATION")
                for name in constraint.outputs
            )
            if abs(input_total - output_total) > constraint.tolerance:
                raise ConstraintViolation("E_CONSERVATION_VIOLATION", constraint.kind)
