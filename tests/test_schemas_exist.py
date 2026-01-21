from pathlib import Path


def test_schema_files_exist() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    schema_paths = [
        repo_root / "schemas/physics/physhir.schema.json",
        repo_root / "schemas/physics/unit_registry.schema.json",
        repo_root / "schemas/physics/constraints.schema.json",
        repo_root / "schemas/causal/causal_graph.schema.json",
        repo_root / "schemas/reality/reality_kernel_config.schema.json",
    ]
    missing = [path for path in schema_paths if not path.exists()]
    assert not missing, f"Missing schema files: {missing}"
