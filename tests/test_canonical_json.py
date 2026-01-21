from evidenceos.common.canonical_json import canonical_dumps_str, stable_object_hash

def test_canonical_key_order() -> None:
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert canonical_dumps_str(a) == canonical_dumps_str(b)

def test_stable_hash_matches_on_reordered_dict() -> None:
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert stable_object_hash(a) == stable_object_hash(b)
