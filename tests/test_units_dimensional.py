import pytest

from evidenceos.physics.units import (
    DIMENSIONLESS,
    Dimension,
    DimensionError,
    add_dimensions,
    exp_dimension,
    log_dimension,
    mul_dimensions,
    parse_dimension,
)


def test_add_mismatched_dimensions_raises() -> None:
    length = parse_dimension("m")
    time = parse_dimension("s")

    with pytest.raises(DimensionError) as excinfo:
        add_dimensions(length, time)

    assert excinfo.value.code == "E_DIMENSIONAL_INVALID"


def test_multiply_dimensions_combines_exponents() -> None:
    length = parse_dimension("m")
    accel = parse_dimension("m/s^2")

    combined = mul_dimensions(length, accel)

    assert combined == Dimension.from_mapping({"L": 2, "T": -2})


def test_exp_log_require_dimensionless() -> None:
    length = parse_dimension("m")

    with pytest.raises(DimensionError) as exp_exc:
        exp_dimension(length)
    assert exp_exc.value.code == "E_DIMENSIONAL_INVALID"

    with pytest.raises(DimensionError) as log_exc:
        log_dimension(length)
    assert log_exc.value.code == "E_DIMENSIONAL_INVALID"

    assert exp_dimension(DIMENSIONLESS).is_dimensionless()
    assert log_dimension(DIMENSIONLESS).is_dimensionless()


def test_parse_units_meters_per_second_squared() -> None:
    dimension = parse_dimension("m/s^2")

    assert dimension == Dimension.from_mapping({"L": 1, "T": -2})


def test_parse_dimensionless_one() -> None:
    dimension = parse_dimension("1")

    assert dimension.is_dimensionless()
