import pytest

from evidenceos.physics.physhir import PhysHIR, PhysHIRCompiler
from evidenceos.physics.typecheck import (
    E_DIMENSIONAL_INVALID,
    E_DIMENSIONAL_TARGET_MISMATCH,
    E_DIMENSIONLESS_REQUIRED,
    DimensionError,
    Typechecker,
)


def _compile(data: dict) -> PhysHIR:
    return PhysHIRCompiler().load(data)


def test_physhir_typecheck_valid() -> None:
    data = {
        "target": {"name": "Y", "units": "m/s^2"},
        "variables": [
            {"name": "X", "units": "m/s"},
            {"name": "T", "units": "s"},
        ],
        "expression": {
            "type": "Div",
            "lhs": {"type": "Var", "name": "X"},
            "rhs": {"type": "Var", "name": "T"},
        },
    }
    physhir = _compile(data)
    Typechecker().validate(physhir)


def test_physhir_typecheck_add_mismatch() -> None:
    data = {
        "target": {"name": "Y", "units": "kg*m/s^2"},
        "variables": [
            {"name": "F", "units": "kg*m/s^2"},
            {"name": "V", "units": "m/s"},
        ],
        "expression": {
            "type": "Add",
            "lhs": {"type": "Var", "name": "F"},
            "rhs": {"type": "Var", "name": "V"},
        },
    }
    physhir = _compile(data)
    with pytest.raises(DimensionError) as exc:
        Typechecker().validate(physhir)
    assert exc.value.code == E_DIMENSIONAL_INVALID


def test_physhir_typecheck_exp_requires_dimensionless() -> None:
    data = {
        "target": {"name": "Y", "units": "1"},
        "variables": [{"name": "X", "units": "m"}],
        "expression": {"type": "Exp", "arg": {"type": "Var", "name": "X"}},
    }
    physhir = _compile(data)
    with pytest.raises(DimensionError) as exc:
        Typechecker().validate(physhir)
    assert exc.value.code == E_DIMENSIONLESS_REQUIRED


def test_physhir_typecheck_target_mismatch() -> None:
    data = {
        "target": {"name": "Y", "units": "m/s^2"},
        "variables": [{"name": "X", "units": "m/s"}],
        "expression": {"type": "Var", "name": "X"},
    }
    physhir = _compile(data)
    with pytest.raises(DimensionError) as exc:
        Typechecker().validate(physhir)
    assert exc.value.code == E_DIMENSIONAL_TARGET_MISMATCH
