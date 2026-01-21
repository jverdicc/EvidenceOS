import json
from pathlib import Path

from evidenceos.admissibility.reality_kernel import RealityKernel


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _base_physhir() -> dict:
    return {
        "quantities": [
            {"name": "a", "value": 2, "unit": "m", "dimension": "L"},
            {"name": "b", "value": 3, "unit": "m", "dimension": "L"},
            {"name": "c", "value": 5, "unit": "m", "dimension": "L"},
        ],
        "constraints": [
            {"id": "sum_1", "type": "sum_equals", "terms": ["a", "b"], "equals": "c"}
        ],
    }


def _base_config() -> dict:
    return {"alpha": 0.05, "prior": 0.5, "e_value": 100.0, "enable_canary": False}


def _base_causal() -> dict:
    return {
        "nodes": [
            {"id": "T", "role": "treatment", "time": 1},
            {"id": "Y", "role": "outcome", "time": 2},
        ],
        "edges": [{"source": "T", "target": "Y"}],
        "adjustments": [],
    }


def test_invalid_units_fail(tmp_path: Path) -> None:
    physhir = _base_physhir()
    physhir["quantities"][0]["unit"] = "lightyear"
    physhir_path = tmp_path / "physhir.json"
    causal_path = tmp_path / "causal.json"
    config_path = tmp_path / "config.json"
    _write_json(physhir_path, physhir)
    _write_json(causal_path, _base_causal())
    _write_json(config_path, _base_config())

    result = RealityKernel().validate_from_files(physhir_path, causal_path, config_path)

    assert result.status == "FAIL"
    assert result.errors[0].code == "SCHEMA_PHYSHIR_INVALID"


def test_temporal_violation_fail(tmp_path: Path) -> None:
    causal = {
        "nodes": [
            {"id": "T", "role": "treatment", "time": 5},
            {"id": "Y", "role": "outcome", "time": 2},
        ],
        "edges": [{"source": "T", "target": "Y"}],
        "adjustments": [],
    }
    physhir_path = tmp_path / "physhir.json"
    causal_path = tmp_path / "causal.json"
    config_path = tmp_path / "config.json"
    _write_json(physhir_path, _base_physhir())
    _write_json(causal_path, causal)
    _write_json(config_path, _base_config())

    result = RealityKernel().validate_from_files(physhir_path, causal_path, config_path)

    assert result.status == "FAIL"
    assert result.errors[0].code == "CAUSAL_TEMPORAL_VIOLATION"


def test_missing_confounder_adjustment_fail(tmp_path: Path) -> None:
    causal = {
        "nodes": [
            {"id": "C", "role": "confounder", "time": 0},
            {"id": "T", "role": "treatment", "time": 1},
            {"id": "Y", "role": "outcome", "time": 2},
        ],
        "edges": [
            {"source": "C", "target": "T"},
            {"source": "C", "target": "Y"},
            {"source": "T", "target": "Y"},
        ],
        "adjustments": [],
    }
    physhir_path = tmp_path / "physhir.json"
    causal_path = tmp_path / "causal.json"
    config_path = tmp_path / "config.json"
    _write_json(physhir_path, _base_physhir())
    _write_json(causal_path, causal)
    _write_json(config_path, _base_config())

    result = RealityKernel().validate_from_files(physhir_path, causal_path, config_path)

    assert result.status == "FAIL"
    assert result.errors[0].code == "CAUSAL_UNADJUSTED_CONFOUNDER"


def test_good_case_pass(tmp_path: Path) -> None:
    causal = {
        "nodes": [
            {"id": "C", "role": "confounder", "time": 0},
            {"id": "T", "role": "treatment", "time": 1},
            {"id": "Y", "role": "outcome", "time": 2},
        ],
        "edges": [
            {"source": "C", "target": "T"},
            {"source": "C", "target": "Y"},
            {"source": "T", "target": "Y"},
        ],
        "adjustments": ["C"],
    }
    physhir_path = tmp_path / "physhir.json"
    causal_path = tmp_path / "causal.json"
    config_path = tmp_path / "config.json"
    _write_json(physhir_path, _base_physhir())
    _write_json(causal_path, causal)
    _write_json(config_path, _base_config())

    result = RealityKernel().validate_from_files(physhir_path, causal_path, config_path)

    assert result.status == "PASS"
    assert result.errors == ()
