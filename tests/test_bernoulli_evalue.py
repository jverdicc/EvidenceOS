import pytest

from evidenceos.evidence.bernoulli_evalue import bernoulli_e_increment


@pytest.mark.parametrize(
    ("x", "p0", "p1"),
    [
        (2, 0.2, 0.1),
        (1, 0.2, 0.2),
        (1, 0.2, 0.3),
        (1, 1.0, 0.5),
        (1, 0.0, 0.0),
    ],
)
def test_invalid_inputs_raise(x: int, p0: float, p1: float) -> None:
    with pytest.raises(ValueError):
        bernoulli_e_increment(x=x, p0=p0, p1=p1)


def test_e_increment_positive() -> None:
    e_fail = bernoulli_e_increment(x=1, p0=0.2, p1=0.1)
    e_pass = bernoulli_e_increment(x=0, p0=0.2, p1=0.1)
    assert e_fail > 0.0
    assert e_pass > 0.0
