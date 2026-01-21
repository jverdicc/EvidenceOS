from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any, Callable, Mapping, Sequence

Path = tuple[str, ...]
JsonLike = Any


def _to_primitive(obj: JsonLike) -> JsonLike:
    if is_dataclass(obj):
        return asdict(obj)
    if hasattr(obj, "model_dump") and callable(getattr(obj, "model_dump")):
        return obj.model_dump(mode="json")
    if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
        return obj.dict()
    return obj


def canonicalize(
    obj: JsonLike,
    *,
    drop_keys: set[str] | None = None,
    drop_paths: set[Path] | None = None,
    drop_predicate: Callable[[Path, JsonLike], bool] | None = None,
    _path: Path = (),
) -> JsonLike:
    drop_keys = drop_keys or set()
    drop_paths = drop_paths or set()

    obj = _to_primitive(obj)

    if drop_predicate is not None and drop_predicate(_path, obj):
        return None

    if isinstance(obj, Mapping):
        out: dict[str, JsonLike] = {}
        for k, v in obj.items():
            ks = k if isinstance(k, str) else str(k)
            child_path = _path + (ks,)
            if ks in drop_keys:
                continue
            if child_path in drop_paths:
                continue
            canon_v = canonicalize(
                v,
                drop_keys=drop_keys,
                drop_paths=drop_paths,
                drop_predicate=drop_predicate,
                _path=child_path,
            )
            if canon_v is None:
                continue
            out[ks] = canon_v
        return out

    if isinstance(obj, (list, tuple)):
        out_list: list[JsonLike] = []
        for i, item in enumerate(obj):
            child_path = _path + (str(i),)
            canon_item = canonicalize(
                item,
                drop_keys=drop_keys,
                drop_paths=drop_paths,
                drop_predicate=drop_predicate,
                _path=child_path,
            )
            if canon_item is None:
                continue
            out_list.append(canon_item)
        return out_list

    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj

    return str(obj)


def canonical_dumps_str(obj: Any) -> str:
    return json.dumps(
        canonicalize(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def canonical_dumps_bytes(obj: Any) -> bytes:
    return canonical_dumps_str(obj).encode("utf-8")


def stable_object_hash(
    obj: Any,
    *,
    drop_keys: set[str] | None = None,
    drop_paths: set[Path] | None = None,
    drop_predicate: Callable[[Path, JsonLike], bool] | None = None,
) -> str:
    payload = json.dumps(
        canonicalize(obj, drop_keys=drop_keys, drop_paths=drop_paths, drop_predicate=drop_predicate),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    import hashlib

    return hashlib.sha256(payload).hexdigest()
