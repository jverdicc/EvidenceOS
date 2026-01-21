from __future__ import annotations

import hashlib
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]


def sha256_bytes(data: BytesLike) -> bytes:
    return hashlib.sha256(bytes(data)).digest()


def sha256_hex(data: BytesLike) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def sha256_prefixed(data: BytesLike) -> str:
    return "sha256:" + sha256_hex(data)
