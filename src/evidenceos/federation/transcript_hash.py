from __future__ import annotations

from typing import Any, Mapping

from evidenceos.common.canonical_json import stable_object_hash

NONDETERMINISTIC_KEYS: set[str] = {
    "timestamp",
    "timestamp_utc",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "duration_ms",
    "trace_id",
    "span_id",
    "request_id",
    "job_id",
    "run_id",
    "nonce",
    "salt",
    "seed",
    "signature",
    "sig",
    "zk_proof",
}


def _drop_predicate(path: tuple[str, ...], value: Any) -> bool:
    if path and path[-1] in {"debug", "_debug", "_meta"}:
        return True
    return False


def transcript_hash(transcript: Mapping[str, Any]) -> str:
    return stable_object_hash(transcript, drop_keys=NONDETERMINISTIC_KEYS, drop_predicate=_drop_predicate)
