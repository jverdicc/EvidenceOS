from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import jsonschema


def load_schema(schema_path: Path) -> Dict[str, Any]:
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_json(instance: Any, schema_path: Path) -> None:
    schema = load_schema(schema_path)
    resolver = jsonschema.RefResolver(base_uri=schema_path.as_uri(), referrer=schema)
    jsonschema.Draft202012Validator(schema, resolver=resolver).validate(instance)
