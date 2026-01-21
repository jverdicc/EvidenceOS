from pathlib import Path


def test_uvp_schema_files_exist() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    schema_paths = [
        repo_root / "schemas" / "uvp" / "uvp_session.schema.json",
        repo_root / "schemas" / "uvp" / "uvp_syscall.schema.json",
        repo_root / "schemas" / "uvp" / "safety_property.schema.json",
        repo_root / "schemas" / "uvp" / "adversarial_hypothesis.schema.json",
        repo_root / "schemas" / "scc" / "scc.schema.json",
    ]

    missing = [path for path in schema_paths if not path.is_file()]

    assert not missing, f"Missing schema files: {missing}"
