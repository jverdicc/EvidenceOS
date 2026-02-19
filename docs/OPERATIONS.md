# Operations Guide

## ETL signing key rotation

EvidenceOS loads signing keys from `<data-dir>/keys/` using `key_id = sha256(ed25519_public_key)`.

### Planned rotation

1. Generate the new 32-byte Ed25519 secret key material offline.
2. Compute key id from the public key and write `<data-dir>/keys/<key_id_hex>.key`.
3. Update `<data-dir>/keys/active_key_id` to the new `key_id` hex value.
4. Restart daemon.
5. Validate by running `GetSignedTreeHead` and `GetPublicKey(key_id=<new_id>)` and verifying the returned signature.

### Historical verification requirement

Do **not** delete old key files immediately. Historical STH verification requires `GetPublicKey` for prior `key_id` values referenced by artifacts.

### Emergency rollback

1. Restore the previous `active_key_id` value.
2. Restart daemon.
3. Confirm new STHs are signed by the rolled-back key id.

### Suspected key compromise workflow

1. Freeze certification traffic at the deployment edge.
2. Rotate immediately to a fresh key as above.
3. Preserve compromised key file for historical verification and incident audit.
4. Re-issue trust distribution artifacts listing compromised key id and validity boundary.
5. Resume traffic after external trust channel confirms accepted replacement key.
