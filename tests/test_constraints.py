import pytest

from evidenceos.physics.constraints import (
    ConservationConstraint,
    ConstraintViolation,
    PinnedPrimary,
    RangeConstraint,
    validate_conservation,
    validate_pinned_primaries,
    validate_ranges,
)


def test_pinned_primary_mismatch_fails() -> None:
    constraints = [
        PinnedPrimary(name="c", units="m/s", value=299_792_458.0, locked=True)
    ]
    physhir = {"c": 299_792_459.0}
    with pytest.raises(ConstraintViolation, match="E_PINNED_PRIMARY_VIOLATION"):
        validate_pinned_primaries(physhir, constraints)


def test_range_constraint_below_absolute_zero_fails() -> None:
    constraints = [RangeConstraint(var="T", min=0.0, max=None, units="K")]
    data_point = {"T": -1.0}
    with pytest.raises(ConstraintViolation, match="E_RANGE_VIOLATION"):
        validate_ranges(data_point, constraints)


def test_conservation_tolerance_passes_and_fails() -> None:
    constraint = ConservationConstraint(
        kind="mass_conservation",
        inputs=["m_in1", "m_in2"],
        outputs=["m_out"],
        tolerance=1e-6,
        units="kg",
    )
    validate_conservation({"m_in1": 1.0, "m_in2": 2.0, "m_out": 3.0}, [constraint])
    with pytest.raises(ConstraintViolation, match="E_CONSERVATION_VIOLATION"):
        validate_conservation({"m_in1": 1.0, "m_in2": 2.0, "m_out": 2.9}, [constraint])
