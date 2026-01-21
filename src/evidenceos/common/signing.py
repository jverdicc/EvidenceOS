from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical_json import canonical_dumps_bytes


@dataclass(frozen=True)
class Ed25519Keypair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @staticmethod
    def generate() -> "Ed25519Keypair":
        sk = Ed25519PrivateKey.generate()
        return Ed25519Keypair(private_key=sk, public_key=sk.public_key())

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_key_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )


def sign_ed25519(keypair: Ed25519Keypair, message_obj: Any) -> str:
    msg = canonical_dumps_bytes(message_obj)
    sig = keypair.private_key.sign(msg)
    return "ed25519:" + sig.hex()


def verify_ed25519(public_key_bytes: bytes, message_obj: Any, signature: str) -> bool:
    if not signature.startswith("ed25519:"):
        return False
    sig_bytes = bytes.fromhex(signature.split(":", 1)[1])
    msg = canonical_dumps_bytes(message_obj)
    pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        pk.verify(sig_bytes, msg)
        return True
    except Exception:
        return False
