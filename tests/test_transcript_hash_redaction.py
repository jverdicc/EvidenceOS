import copy
import uuid

from evidenceos.federation.transcript_hash import transcript_hash

def test_transcript_hash_ignores_nondeterminism() -> None:
    t = {
        "federation_id": "fed1",
        "responses": [
            {"vault_id":"A","e_value":2.0,"timestamp_utc":"t1","signature":"sig1","nonce":"n1"}
        ],
    }
    h1 = transcript_hash(t)
    t2 = copy.deepcopy(t)
    t2["responses"][0]["timestamp_utc"] = "t2"
    t2["responses"][0]["signature"] = "sig2"
    t2["responses"][0]["nonce"] = str(uuid.uuid4())
    h2 = transcript_hash(t2)
    assert h1 == h2

def test_transcript_hash_changes_on_semantic_change() -> None:
    t = {"responses":[{"vault_id":"A","e_value":2.0}]}
    h1 = transcript_hash(t)
    t2 = {"responses":[{"vault_id":"A","e_value":999.0}]}
    h2 = transcript_hash(t2)
    assert h1 != h2
