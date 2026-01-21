from evidenceos.common.signing import Ed25519Keypair, sign_ed25519, verify_ed25519

def test_sign_verify() -> None:
    kp = Ed25519Keypair.generate()
    msg = {"a": 1, "b": 2}
    sig = sign_ed25519(kp, msg)
    assert verify_ed25519(kp.public_key_bytes(), msg, sig)

def test_verify_fail_on_modified_msg() -> None:
    kp = Ed25519Keypair.generate()
    msg = {"a": 1, "b": 2}
    sig = sign_ed25519(kp, msg)
    assert not verify_ed25519(kp.public_key_bytes(), {"a": 1, "b": 3}, sig)
