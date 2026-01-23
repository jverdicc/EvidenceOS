from __future__ import annotations

import math


def encode_fixed_width_int(value: int, bits: int) -> bytes:
    if bits <= 0:
        raise ValueError("bits must be > 0")
    if value < 0:
        raise ValueError("value must be >= 0")
    max_value = (1 << bits) - 1
    if value > max_value:
        raise ValueError("value exceeds bit width")
    length = int(math.ceil(bits / 8))
    return value.to_bytes(length, byteorder="big")
