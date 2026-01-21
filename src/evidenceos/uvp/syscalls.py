from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evidenceos.causal.canary import DataBatch, add_noise, invariance_test, rescale, shuffle
from evidenceos.causal.dag import CausalGraphParseError, parse_causal_graph
from evidenceos.common.canonical_json import canonical_dumps_bytes
from evidenceos.common.hashing import sha256_prefixed
from evidenceos.common.schema_validate import validate_json
from evidenceos.common.signing import Ed25519Keypair, sign_ed25519
from evidenceos.physics.constraints import (
    ConstraintViolation,
    validate_conservation,
    validate_pinned_primaries,
    validate_ranges,
)
from evidenceos.physics.hir_ast import parse_expr
from evidenceos.physics.physhir import PhysHIR, TargetSpec, VariableSpec
from evidenceos.physics.typecheck import DimensionError, Typechecker

from .session_store import (
    ANNOUNCE_SCHEMA,
    CAUSAL_SCHEMA,
    EVALUATION_SCHEMA,
    EWL_STATE_SCHEMA,
    EWL_VERSION,
    GATE_REPORT_SCHEMA,
    GATE_REPORT_VERSION,
    PHYSHIR_SCHEMA,
    PROPOSE_SCHEMA,
    SCC_SCHEMA,
    SCC_VERSION,
    UVP_VERSION,
    EWLState,
    SessionPaths,
    append_jsonl,
    ensure_session_dir,
    load_announce,
    load_ewl_state,
    load_gate_report,
    load_propose,
    read_jsonl,
    session_paths,
    write_json,
)


class UVPError(RuntimeError):
    pass


@dataclass(frozen=True)
class EWLPolicy:
    null_p: float
    alt_p: float
    initial_wealth: float
    bankruptcy_floor: float


@dataclass(frozen=True)
class EvaluationEntry:
    index: int
    hypothesis: str
    outcome_x: int
    meta: dict[str, Any]
    status: str
    gate_status: str
    gate_errors: tuple[str, ...]
    e_increment: float
    ewl_before: float
    ewl_after: float

    def to_obj(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "hypothesis": self.hypothesis,
            "outcome_x": self.outcome_x,
            "meta": self.meta,
            "status": self.status,
            "gate_status": self.gate_status,
            "gate_errors": list(self.gate_errors),
            "e_increment": self.e_increment,
            "ewl_before": self.ewl_before,
            "ewl_after": self.ewl_after,
        }


@dataclass(frozen=True)
class SCCPayload:
    version: str
    session_id: str
    timestamp_utc: str
    announce: dict[str, Any]
    propose: dict[str, Any]
    evaluations: list[dict[str, Any]]
    ewl_state: dict[str, Any]
    reality_gate_report: dict[str, Any]
    kernel_public_key: str
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from evidenceos.common.canonical_json import canonical_dumps_bytes
from evidenceos.common.hashing import sha256_prefixed


def _normalize_strings(values: Sequence[str]) -> list[str]:
    if any(not isinstance(v, str) or not v for v in values):
        raise ValueError("all entries must be non-empty strings")
    return sorted(set(values))


def _hash_payload(payload: Mapping[str, Any]) -> str:
    return sha256_prefixed(canonical_dumps_bytes(payload))


@dataclass(frozen=True)
class UVPEvent:
    seq: int
    syscall: str
    payload: dict[str, Any]
    payload_hash: str

    def to_obj(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "syscall": self.syscall,
            "payload_hash": self.payload_hash,
            "payload": self.payload,
        }


@dataclass
class UVPTranscript:
    version: str = "v1"
    events: list[UVPEvent] = field(default_factory=list)

    def append(self, syscall: str, payload: Mapping[str, Any]) -> UVPEvent:
        seq = len(self.events) + 1
        payload_dict = dict(payload)
        payload_hash = _hash_payload(payload_dict)
        event = UVPEvent(seq=seq, syscall=syscall, payload=payload_dict, payload_hash=payload_hash)
        self.events.append(event)
        return event

    def to_obj(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "session_id": self.session_id,
            "timestamp_utc": self.timestamp_utc,
            "announce": self.announce,
            "propose": self.propose,
            "evaluations": self.evaluations,
            "ewl_state": self.ewl_state,
            "reality_gate_report": self.reality_gate_report,
            "kernel_public_key": self.kernel_public_key,
        }


class MeanEvaluator:
    def __init__(self, variable: str) -> None:
        self._variable = variable

    def evaluate(self, data_batch: DataBatch) -> float:
        if self._variable not in data_batch:
            raise ValueError(f"missing_variable:{self._variable}")
        values = data_batch[self._variable]
        if not values:
            raise ValueError("empty_variable")
        return float(sum(values) / len(values))


def uvp_announce(session_dir: Path | str, pds_manifest: Mapping[str, Any]) -> dict[str, Any]:
    session_path = Path(session_dir)
    ensure_session_dir(session_path)
    paths = session_paths(session_path)
    session_id = session_path.name
    announce = {
        "uvp_version": UVP_VERSION,
        "session_id": session_id,
        "pds_manifest": dict(pds_manifest),
    }
    write_json(paths.announce_path, announce, ANNOUNCE_SCHEMA)

    policy = _parse_ewl_policy(pds_manifest)
    ewl_state = EWLState(
        version=EWL_VERSION,
        wealth=policy.initial_wealth,
        bankruptcy_floor=policy.bankruptcy_floor,
        last_increment=1.0,
        updates=0,
        bankrupt=False,
    )
    write_json(paths.ewl_state_path, ewl_state.to_obj(), EWL_STATE_SCHEMA)

    if not paths.reality_gate_report_path.exists():
        report_obj = {"version": GATE_REPORT_VERSION, "entries": []}
        write_json(paths.reality_gate_report_path, report_obj, GATE_REPORT_SCHEMA)

    if not paths.evaluations_path.exists():
        paths.evaluations_path.write_text("", encoding="utf-8")

    return announce


def uvp_propose(
    session_dir: Path | str,
    causal_dag: Mapping[str, Any],
    physhir: Mapping[str, Any],
    payload_hashes: list[Mapping[str, Any]],
) -> dict[str, Any]:
    session_path = Path(session_dir)
    ensure_session_dir(session_path)
    paths = session_paths(session_path)
    _ = load_announce(paths)
    propose = {
        "uvp_version": UVP_VERSION,
        "session_id": session_path.name,
        "causal_dag": dict(causal_dag),
        "physhir": dict(physhir),
        "payload_hashes": [dict(item) for item in payload_hashes],
    }
    write_json(paths.propose_path, propose, PROPOSE_SCHEMA)
    return propose


def uvp_evaluate(
    session_dir: Path | str,
    hypothesis: str,
    outcome_x: int,
    meta: Mapping[str, Any],
) -> dict[str, Any]:
    if outcome_x not in (0, 1):
        raise ValueError("outcome_x must be 0 or 1")

    session_path = Path(session_dir)
    ensure_session_dir(session_path)
    paths = session_paths(session_path)
    announce = load_announce(paths)
    propose = load_propose(paths)
    ewl_state = load_ewl_state(paths)
    gate_report = load_gate_report(paths)

    manifest = announce["pds_manifest"]
    gates_cfg = manifest["reality_gates"]
    gate_results = {
        "physhir": "SKIPPED",
        "causal_dag": "SKIPPED",
        "canary": "SKIPPED",
        "ewl": "SKIPPED",
    }
    gate_errors: list[str] = []

    if bool(gates_cfg["require_physhir"]):
        errors = _run_physhir_gate(propose["physhir"])
        if errors:
            gate_results["physhir"] = "FAIL"
            gate_errors.extend(errors)
        else:
            gate_results["physhir"] = "PASS"

    if bool(gates_cfg["require_causal_dag"]):
        errors = _run_causal_gate(propose["causal_dag"])
        if errors:
            gate_results["causal_dag"] = "FAIL"
            gate_errors.extend(errors)
        else:
            gate_results["causal_dag"] = "PASS"

    if bool(gates_cfg["require_canary"]):
        canary_cfg = manifest.get("canary_config")
        errors = _run_canary_gate(canary_cfg)
        if errors:
            gate_results["canary"] = "FAIL"
            gate_errors.extend(errors)
        else:
            gate_results["canary"] = "PASS"

    if ewl_state.bankrupt or ewl_state.wealth <= ewl_state.bankruptcy_floor:
        gate_results["ewl"] = "FAIL"
        gate_errors.append("EWL_BANKRUPT")
    else:
        gate_results["ewl"] = "PASS"

    gate_ok = not gate_errors
    gate_entry = {
        "index": len(gate_report["entries"]),
        "status": "PASS" if gate_ok else "FAIL",
        "errors": list(gate_errors),
        "gates": gate_results,
    }
    gate_report["entries"].append(gate_entry)
    write_json(paths.reality_gate_report_path, gate_report, GATE_REPORT_SCHEMA)

    evaluations = read_jsonl(paths.evaluations_path)
    if gate_ok:
        policy = _parse_ewl_policy(manifest)
        e_increment = bernoulli_e_increment(outcome_x, policy.null_p, policy.alt_p)
        ewl_before = ewl_state.wealth
        ewl_after = ewl_before * e_increment
        ewl_state = EWLState(
            version=ewl_state.version,
            wealth=ewl_after,
            bankruptcy_floor=ewl_state.bankruptcy_floor,
            last_increment=e_increment,
            updates=ewl_state.updates + 1,
            bankrupt=ewl_after <= ewl_state.bankruptcy_floor,
        )
        write_json(paths.ewl_state_path, ewl_state.to_obj(), EWL_STATE_SCHEMA)
        status = "VALID"
        gate_status = "PASS"
    else:
        ewl_before = ewl_state.wealth
        ewl_after = ewl_before
        e_increment = 0.0
        status = "INVALID"
        gate_status = "FAIL"

    entry = EvaluationEntry(
        index=len(evaluations),
        hypothesis=hypothesis,
        outcome_x=outcome_x,
        meta=dict(meta),
        status=status,
        gate_status=gate_status,
        gate_errors=tuple(gate_errors),
        e_increment=e_increment,
        ewl_before=ewl_before,
        ewl_after=ewl_after,
    )
    append_jsonl(paths.evaluations_path, entry.to_obj(), EVALUATION_SCHEMA)
    return entry.to_obj()


def uvp_certify(
    session_dir: Path | str, keypair: Ed25519Keypair, timestamp_utc: str
) -> dict[str, Any]:
    session_path = Path(session_dir)
    ensure_session_dir(session_path)
    paths = session_paths(session_path)

    announce = load_announce(paths)
    propose = load_propose(paths)
    evaluations = _load_evaluations(paths)
    ewl_state = load_ewl_state(paths)
    gate_report = load_gate_report(paths)

    kernel_public_key = _format_public_key(keypair)
    payload = SCCPayload(
        version=SCC_VERSION,
        session_id=session_path.name,
        timestamp_utc=timestamp_utc,
        announce=announce,
        propose=propose,
        evaluations=evaluations,
        ewl_state=ewl_state.to_obj(),
        reality_gate_report=gate_report,
        kernel_public_key=kernel_public_key,
    )
    payload_obj = payload.to_obj()
    scc_hash = sha256_prefixed(canonical_dumps_bytes(payload_obj))
    payload_with_hash = {**payload_obj, "scc_hash": scc_hash}
    signature = sign_ed25519(keypair, payload_with_hash)
    scc = {**payload_with_hash, "signature": signature}
    write_json(paths.scc_path, scc, SCC_SCHEMA)
    return scc


def bernoulli_e_increment(outcome_x: int, null_p: float, alt_p: float) -> float:
    if not (0.0 < null_p < 1.0):
        raise ValueError("null_p must be in (0,1)")
    if not (0.0 < alt_p < 1.0):
        raise ValueError("alt_p must be in (0,1)")
    if outcome_x not in (0, 1):
        raise ValueError("outcome_x must be 0 or 1")

    if outcome_x == 1:
        value = alt_p / null_p
    else:
        value = (1.0 - alt_p) / (1.0 - null_p)

    if not math.isfinite(value) or value < 0:
        raise ValueError("e_increment_invalid")
    return value


def keypair_from_private_hex(private_key_hex: str) -> Ed25519Keypair:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return Ed25519Keypair(private_key=private_key, public_key=private_key.public_key())


def scc_payload_for_verify(scc_obj: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(scc_obj)
    payload.pop("signature", None)
    return payload


def _parse_ewl_policy(manifest: Mapping[str, Any]) -> EWLPolicy:
    policy = manifest.get("ewl_policy")
    if not isinstance(policy, Mapping):
        raise UVPError("ewl_policy_missing")
    return EWLPolicy(
        null_p=float(policy["null_p"]),
        alt_p=float(policy["alt_p"]),
        initial_wealth=float(policy["initial_wealth"]),
        bankruptcy_floor=float(policy["bankruptcy_floor"]),
    )


def _run_physhir_gate(physhir: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        validate_json(physhir, PHYSHIR_SCHEMA)
    except jsonschema.ValidationError:
        return ["PHYSHIR_SCHEMA_INVALID"]

    try:
        compiled = _compile_physhir(physhir)
    except (KeyError, TypeError, ValueError):
        return ["PHYSHIR_PARSE_ERROR"]

    try:
        Typechecker().validate(compiled)
    except DimensionError as exc:
        return [exc.code]

    constraints = physhir.get("constraints", {})
    observations = physhir.get("observations", {})
    if constraints:
        if not isinstance(observations, Mapping):
            return ["PHYSHIR_OBSERVATIONS_INVALID"]
        try:
            validate_pinned_primaries(observations, constraints.get("pinned_primaries", []))
            validate_ranges(observations, constraints.get("ranges", []))
            validate_conservation(observations, constraints.get("conservation", []))
        except ConstraintViolation as exc:
            errors.append(exc.code)
        except (TypeError, ValueError):
            errors.append("PHYSHIR_CONSTRAINT_INVALID")
    return errors


def _compile_physhir(physhir: Mapping[str, Any]) -> PhysHIR:
    target = physhir["target"]
    target_spec = TargetSpec(name=str(target["name"]), units=str(target["units"]))
    variables_raw = physhir["variables"]
    variables = tuple(
        VariableSpec(name=str(item["name"]), units=str(item["units"]))
        for item in variables_raw
    )
    expression = parse_expr(physhir["expression"])
    return PhysHIR(target=target_spec, variables=variables, expression=expression)


def _run_causal_gate(causal_dag: Mapping[str, Any]) -> list[str]:
    try:
        validate_json(causal_dag, CAUSAL_SCHEMA)
    except jsonschema.ValidationError:
        return ["CAUSAL_SCHEMA_INVALID"]

    try:
        graph = parse_causal_graph(causal_dag)
    except CausalGraphParseError:
        return ["CAUSAL_PARSE_INVALID"]

    errors: list[str] = []
    node_ids = set(graph.node_ids())
    if graph.treatment not in node_ids:
        errors.append("CAUSAL_TREATMENT_UNKNOWN")
    if graph.outcome not in node_ids:
        errors.append("CAUSAL_OUTCOME_UNKNOWN")
    for node_id in graph.adjustment_set:
        if node_id not in node_ids:
            errors.append("CAUSAL_ADJUSTMENT_UNKNOWN")
            break

    time_index = {node.node_id: node.time_index for node in graph.nodes}
    for edge in graph.edges:
        if time_index[edge.src] > time_index[edge.dst]:
            errors.append("CAUSAL_TEMPORAL_VIOLATION")
            break

    if _has_cycle(node_ids, graph.edges):
        errors.append("CAUSAL_DAG_CYCLE")

    return errors


def _run_canary_gate(canary_cfg: Any) -> list[str]:
    if canary_cfg is None:
        return ["CANARY_CONFIG_MISSING"]
    if not isinstance(canary_cfg, Mapping):
        return ["CANARY_CONFIG_INVALID"]

    try:
        data_batch = dict(canary_cfg["data_batch"])
        evaluator_cfg = canary_cfg["evaluator"]
        evaluator = MeanEvaluator(variable=str(evaluator_cfg["variable"]))
        transforms = _build_transforms(canary_cfg["transforms"])
        tolerance = float(canary_cfg["tolerance"])
        result = invariance_test(evaluator, data_batch, transforms, tolerance)
    except (KeyError, TypeError, ValueError):
        return ["CANARY_CONFIG_INVALID"]

    if result.flag:
        return [result.flag]
    return []


def _build_transforms(raw_transforms: Any) -> list[Any]:
    transforms: list[Any] = []
    if not isinstance(raw_transforms, list):
        raise ValueError("transforms_invalid")
    for item in raw_transforms:
        if not isinstance(item, Mapping):
            raise ValueError("transform_invalid")
        transform_type = item.get("type")
        if transform_type == "shuffle":
            transforms.append(shuffle(str(item["var"])))
        elif transform_type == "add_noise":
            transforms.append(
                add_noise(
                    str(item["var"]),
                    float(item["sigma"]),
                    int(item["seed"]),
                )
            )
        elif transform_type == "rescale":
            transforms.append(rescale(str(item["var"]), float(item["factor"])))
        else:
            raise ValueError("transform_invalid")
    return transforms


def _has_cycle(node_ids: set[str], edges: tuple[Any, ...]) -> bool:
    adjacency: dict[str, list[str]] = {node: [] for node in node_ids}
    for edge in edges:
        adjacency[edge.src].append(edge.dst)
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

    for node in sorted(node_ids):
        if visit(node):
            return True
    return False


def _format_public_key(keypair: Ed25519Keypair) -> str:
    return "ed25519:" + keypair.public_key_bytes().hex()


def _load_evaluations(paths: SessionPaths) -> list[dict[str, Any]]:
    entries = read_jsonl(paths.evaluations_path)
    for entry in entries:
        validate_json(entry, EVALUATION_SCHEMA)
    return entries


__all__ = [
    "EWLPolicy",
    "EvaluationEntry",
    "MeanEvaluator",
    "SCCPayload",
    "UVPError",
    "bernoulli_e_increment",
    "keypair_from_private_hex",
    "scc_payload_for_verify",
    "uvp_announce",
    "uvp_certify",
    "uvp_evaluate",
    "uvp_propose",
            "events": [event.to_obj() for event in self.events],
        }


@dataclass(frozen=True)
class UVPAnnouncement:
    claim_id: str
    claim: str
    safety_properties: tuple[str, ...]
    adversarial_hypotheses: tuple[str, ...]
    announcement_hash: str


@dataclass(frozen=True)
class UVPProposal:
    announcement_hash: str
    evidence_items: tuple[str, ...]
    resources_requested: float
    proposal_hash: str


@dataclass(frozen=True)
class UVPEvaluation:
    proposal_hash: str
    reality_status: str
    resources_spent: float
    wealth_after: float
    evaluation_hash: str


@dataclass(frozen=True)
class UVPCertification:
    evaluation_hash: str
    decision_trace: dict[str, Any]
    certification_hash: str


class UVPInterface:
    def __init__(self, transcript: UVPTranscript | None = None) -> None:
        self.transcript = transcript or UVPTranscript()

    def announce(
        self,
        *,
        claim_id: str,
        claim: str,
        safety_properties: Sequence[str],
        adversarial_hypotheses: Sequence[str],
    ) -> UVPAnnouncement:
        if not claim_id:
            raise ValueError("claim_id required")
        if not claim:
            raise ValueError("claim required")
        payload = {
            "claim_id": claim_id,
            "claim": claim,
            "safety_properties": _normalize_strings(safety_properties),
            "adversarial_hypotheses": _normalize_strings(adversarial_hypotheses),
        }
        event = self.transcript.append("announce", payload)
        return UVPAnnouncement(
            claim_id=claim_id,
            claim=claim,
            safety_properties=tuple(payload["safety_properties"]),
            adversarial_hypotheses=tuple(payload["adversarial_hypotheses"]),
            announcement_hash=event.payload_hash,
        )

    def propose(
        self,
        *,
        announcement_hash: str,
        evidence_items: Sequence[str],
        resources_requested: float,
    ) -> UVPProposal:
        if resources_requested < 0:
            raise ValueError("resources_requested must be >= 0")
        if not announcement_hash:
            raise ValueError("announcement_hash required")
        payload = {
            "announcement_hash": announcement_hash,
            "evidence_items": _normalize_strings(evidence_items),
            "resources_requested": resources_requested,
        }
        event = self.transcript.append("propose", payload)
        return UVPProposal(
            announcement_hash=announcement_hash,
            evidence_items=tuple(payload["evidence_items"]),
            resources_requested=resources_requested,
            proposal_hash=event.payload_hash,
        )

    def evaluate(
        self,
        *,
        proposal_hash: str,
        reality_status: str,
        resources_spent: float,
        wealth_after: float,
    ) -> UVPEvaluation:
        if not proposal_hash:
            raise ValueError("proposal_hash required")
        if resources_spent < 0:
            raise ValueError("resources_spent must be >= 0")
        payload = {
            "proposal_hash": proposal_hash,
            "reality_status": reality_status,
            "resources_spent": resources_spent,
            "wealth_after": wealth_after,
        }
        event = self.transcript.append("evaluate", payload)
        return UVPEvaluation(
            proposal_hash=proposal_hash,
            reality_status=reality_status,
            resources_spent=resources_spent,
            wealth_after=wealth_after,
            evaluation_hash=event.payload_hash,
        )

    def certify(
        self,
        *,
        evaluation_hash: str,
        decision_trace: Mapping[str, Any],
    ) -> UVPCertification:
        if not evaluation_hash:
            raise ValueError("evaluation_hash required")
        payload = {"evaluation_hash": evaluation_hash, "decision_trace": dict(decision_trace)}
        event = self.transcript.append("certify", payload)
        return UVPCertification(
            evaluation_hash=evaluation_hash,
            decision_trace=payload["decision_trace"],
            certification_hash=event.payload_hash,
        )


__all__ = [
    "UVPAnnouncement",
    "UVPCertification",
    "UVPEvaluation",
    "UVPEvent",
    "UVPInterface",
    "UVPProposal",
    "UVPTranscript",
]
