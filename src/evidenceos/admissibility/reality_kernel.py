from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema

from evidenceos.common.schema_validate import validate_json

SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas" / "reality_kernel"

PHYSHIR_SCHEMA = SCHEMA_DIR / "physhir.schema.json"
CAUSAL_SCHEMA = SCHEMA_DIR / "causal.schema.json"
CONFIG_SCHEMA = SCHEMA_DIR / "reality_config.schema.json"

UNIT_DIMENSIONS: dict[str, str] = {
    "m": "L",
    "s": "T",
    "kg": "M",
    "N": "M*L/T^2",
    "J": "M*L^2/T^2",
}


def _load_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    return payload


@dataclass(frozen=True)
class AdmissibilityError:
    code: str
    message: str


@dataclass(frozen=True)
class AdmissibilityResult:
    status: str
    errors: tuple[AdmissibilityError, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.status == "PASS"


class RealityKernel:
    def validate_from_files(
        self, physhir_path: Path, causal_path: Path, config_path: Path
    ) -> AdmissibilityResult:
        errors: list[AdmissibilityError] = []
        warnings: list[str] = []
        try:
            physhir = _load_json(physhir_path)
        except (OSError, ValueError) as exc:
            errors.append(AdmissibilityError("PHYSHIR_LOAD_ERROR", str(exc)))
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))
        try:
            causal = _load_json(causal_path)
        except (OSError, ValueError) as exc:
            errors.append(AdmissibilityError("CAUSAL_LOAD_ERROR", str(exc)))
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))
        try:
            config = _load_json(config_path)
        except (OSError, ValueError) as exc:
            errors.append(AdmissibilityError("CONFIG_LOAD_ERROR", str(exc)))
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))

        return self.validate_payloads(physhir, causal, config)

    def validate_payloads(
        self, physhir: dict[str, Any], causal: dict[str, Any], config: dict[str, Any]
    ) -> AdmissibilityResult:
        errors: list[AdmissibilityError] = []
        warnings: list[str] = []

        errors.extend(self._validate_schemas(physhir, causal, config))
        if errors:
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))

        errors.extend(self._validate_physhir(physhir))
        if errors:
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))

        errors.extend(self._validate_causal(causal))
        if errors:
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))

        errors.extend(self._validate_canaries(causal, config))
        if errors:
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))

        errors.extend(self._validate_eprocess(config))
        if errors:
            return AdmissibilityResult("FAIL", tuple(errors), tuple(warnings))

        return AdmissibilityResult("PASS", tuple(errors), tuple(warnings))

    def _validate_schemas(
        self, physhir: dict[str, Any], causal: dict[str, Any], config: dict[str, Any]
    ) -> list[AdmissibilityError]:
        errors: list[AdmissibilityError] = []
        try:
            validate_json(physhir, PHYSHIR_SCHEMA)
        except jsonschema.ValidationError as exc:
            errors.append(AdmissibilityError("SCHEMA_PHYSHIR_INVALID", exc.message))
            return errors
        try:
            validate_json(causal, CAUSAL_SCHEMA)
        except jsonschema.ValidationError as exc:
            errors.append(AdmissibilityError("SCHEMA_CAUSAL_INVALID", exc.message))
            return errors
        try:
            validate_json(config, CONFIG_SCHEMA)
        except jsonschema.ValidationError as exc:
            errors.append(AdmissibilityError("SCHEMA_CONFIG_INVALID", exc.message))
            return errors
        return errors

    def _validate_physhir(self, physhir: dict[str, Any]) -> list[AdmissibilityError]:
        errors: list[AdmissibilityError] = []
        quantities = physhir["quantities"]
        value_map = {q["name"]: q["value"] for q in quantities}
        for quantity in quantities:
            unit = quantity["unit"]
            dimension = quantity["dimension"]
            expected = UNIT_DIMENSIONS.get(unit)
            if expected is None:
                errors.append(
                    AdmissibilityError(
                        "PHYSHIR_UNIT_UNKNOWN",
                        f"unit {unit} is not registered",
                    )
                )
                continue
            if dimension != expected:
                errors.append(
                    AdmissibilityError(
                        "PHYSHIR_DIMENSION_MISMATCH",
                        f"quantity {quantity['name']} has dimension {dimension}",
                    )
                )

        for constraint in physhir.get("constraints", []):
            if constraint["type"] == "sum_equals":
                terms = constraint["terms"]
                missing = [name for name in [*terms, constraint["equals"]] if name not in value_map]
                if missing:
                    errors.append(
                        AdmissibilityError(
                            "PHYSHIR_CONSTRAINT_UNKNOWN_QUANTITY",
                            f"constraint {constraint['id']} references {','.join(missing)}",
                        )
                    )
                    continue
                total = sum(value_map[name] for name in terms)
                expected_value = value_map[constraint["equals"]]
                if total != expected_value:
                    errors.append(
                        AdmissibilityError(
                            "PHYSHIR_CONSERVATION_FAIL",
                            f"constraint {constraint['id']} violated",
                        )
                    )
        return errors

    def _validate_causal(self, causal: dict[str, Any]) -> list[AdmissibilityError]:
        errors: list[AdmissibilityError] = []
        node_times = {node["id"]: node["time"] for node in causal["nodes"]}
        node_roles = {node["id"]: node["role"] for node in causal["nodes"]}

        edges = causal["edges"]
        for edge in edges:
            source = edge["source"]
            target = edge["target"]
            if node_times[source] > node_times[target]:
                errors.append(
                    AdmissibilityError(
                        "CAUSAL_TEMPORAL_VIOLATION",
                        f"edge {source}->{target} violates temporal order",
                    )
                )
                return errors

        if self._has_cycle(node_times.keys(), edges):
            errors.append(
                AdmissibilityError("CAUSAL_DAG_CYCLE", "causal graph has a cycle")
            )
            return errors

        adjustments = set(causal.get("adjustments", []))
        treatments = {node_id for node_id, role in node_roles.items() if role == "treatment"}
        outcomes = {node_id for node_id, role in node_roles.items() if role == "outcome"}
        confounders = {node_id for node_id, role in node_roles.items() if role == "confounder"}
        confounder_targets = self._edges_from(edges)
        for confounder in sorted(confounders):
            targets = confounder_targets.get(confounder, set())
            if targets & treatments and targets & outcomes and confounder not in adjustments:
                errors.append(
                    AdmissibilityError(
                        "CAUSAL_UNADJUSTED_CONFOUNDER",
                        f"confounder {confounder} missing adjustment",
                    )
                )
                return errors
        return errors

    def _validate_canaries(
        self, causal: dict[str, Any], config: dict[str, Any]
    ) -> list[AdmissibilityError]:
        errors: list[AdmissibilityError] = []
        if not config.get("enable_canary", False):
            return errors
        canaries = config.get("canaries", [])
        if not canaries:
            errors.append(
                AdmissibilityError(
                    "CAUSAL_CANARY_MISSING", "canary checks enabled but no canaries provided"
                )
            )
            return errors
        canary_nodes = {node["id"] for node in causal["nodes"] if node["role"] == "canary"}
        for canary in canaries:
            canary_id = canary["id"]
            if canary_id not in canary_nodes:
                errors.append(
                    AdmissibilityError(
                        "CAUSAL_CANARY_MISSING",
                        f"canary node {canary_id} not found",
                    )
                )
                return errors
            if not canary["invariant"]:
                errors.append(
                    AdmissibilityError(
                        "CAUSAL_CANARY_VIOLATION",
                        f"canary {canary_id} failed invariance",
                    )
                )
                return errors
        return errors

    def _validate_eprocess(self, config: dict[str, Any]) -> list[AdmissibilityError]:
        errors: list[AdmissibilityError] = []
        alpha = float(config["alpha"])
        prior = float(config["prior"])
        e_value = float(config["e_value"])
        if not (0.0 < alpha < 1.0):
            errors.append(AdmissibilityError("JUDGE_ALPHA_INVALID", "alpha must be in (0,1)"))
            return errors
        if not (0.0 < prior <= 1.0):
            errors.append(AdmissibilityError("JUDGE_PRIOR_INVALID", "prior must be in (0,1]"))
            return errors
        threshold = 1.0 / (alpha * prior)
        if e_value < threshold:
            errors.append(
                AdmissibilityError(
                    "JUDGE_EVALUE_FAIL",
                    f"e_value below threshold {threshold:.6f}",
                )
            )
        return errors

    @staticmethod
    def _edges_from(edges: Sequence[dict[str, str]]) -> dict[str, set[str]]:
        output: dict[str, set[str]] = {}
        for edge in edges:
            output.setdefault(edge["source"], set()).add(edge["target"])
        return output

    @staticmethod
    def _has_cycle(nodes: Iterable[str], edges: Sequence[dict[str, str]]) -> bool:
        adjacency: dict[str, list[str]] = {node: [] for node in nodes}
        for edge in edges:
            adjacency[edge["source"]].append(edge["target"])
        for targets in adjacency.values():
            targets.sort()

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            for neighbor in adjacency.get(node, []):
                if visit(neighbor):
                    return True
            visiting.remove(node)
            visited.add(node)
            return False

        for node in sorted(nodes):
            if visit(node):
                return True
        return False
