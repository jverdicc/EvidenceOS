from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evidenceos.common.canonical_json import canonical_dumps_str
from evidenceos.common.schema_validate import validate_json

UVP_VERSION = "uvp-0.1"
SCC_VERSION = "scc-0.1"
EWL_VERSION = "ewl-0.1"
GATE_REPORT_VERSION = "gate-report-0.1"

SCHEMA_DIR = Path(__file__).resolve().parents[3] / "schemas" / "uvp"
ANNOUNCE_SCHEMA = SCHEMA_DIR / "announce.schema.json"
PROPOSE_SCHEMA = SCHEMA_DIR / "propose.schema.json"
EVALUATION_SCHEMA = SCHEMA_DIR / "evaluation.schema.json"
EWL_STATE_SCHEMA = SCHEMA_DIR / "ewl_state.schema.json"
GATE_REPORT_SCHEMA = SCHEMA_DIR / "reality_gate_report.schema.json"
SCC_SCHEMA = SCHEMA_DIR / "scc.schema.json"
PHYSHIR_SCHEMA = SCHEMA_DIR / "physhir.schema.json"
CAUSAL_SCHEMA = SCHEMA_DIR / "causal_dag.schema.json"


class SessionStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class SessionPaths:
    root: Path
    announce_path: Path
    propose_path: Path
    evaluations_path: Path
    ewl_state_path: Path
    reality_gate_report_path: Path
    scc_path: Path


@dataclass(frozen=True)
class EWLState:
    version: str
    wealth: float
    bankruptcy_floor: float
    last_increment: float
    updates: int
    bankrupt: bool

    def to_obj(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "wealth": self.wealth,
            "bankruptcy_floor": self.bankruptcy_floor,
            "last_increment": self.last_increment,
            "updates": self.updates,
            "bankrupt": self.bankrupt,
        }


@dataclass(frozen=True)
class GateReportEntry:
    index: int
    status: str
    errors: tuple[str, ...]
    gates: dict[str, str]

    def to_obj(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "status": self.status,
            "errors": list(self.errors),
            "gates": dict(self.gates),
        }


def session_paths(session_dir: Path) -> SessionPaths:
    return SessionPaths(
        root=session_dir,
        announce_path=session_dir / "announce.json",
        propose_path=session_dir / "propose.json",
        evaluations_path=session_dir / "evaluations.jsonl",
        ewl_state_path=session_dir / "ewl_state.json",
        reality_gate_report_path=session_dir / "reality_gate_report.json",
        scc_path=session_dir / "scc.json",
    )


def init_session_dir(session_dir: Path) -> None:
    session_dir.mkdir(parents=True, exist_ok=True)
    paths = session_paths(session_dir)
    existing = [
        paths.announce_path,
        paths.propose_path,
        paths.evaluations_path,
        paths.ewl_state_path,
        paths.reality_gate_report_path,
        paths.scc_path,
    ]
    if any(path.exists() for path in existing):
        raise SessionStoreError("session_dir_not_empty")

    paths.evaluations_path.write_text("", encoding="utf-8")
    default_state = EWLState(
        version=EWL_VERSION,
        wealth=1.0,
        bankruptcy_floor=0.0,
        last_increment=1.0,
        updates=0,
        bankrupt=False,
    )
    write_json(paths.ewl_state_path, default_state.to_obj(), EWL_STATE_SCHEMA)
    report_obj = {"version": GATE_REPORT_VERSION, "entries": []}
    write_json(paths.reality_gate_report_path, report_obj, GATE_REPORT_SCHEMA)


def ensure_session_dir(session_dir: Path) -> None:
    if not session_dir.exists():
        raise SessionStoreError("session_dir_missing")
    if not session_dir.is_dir():
        raise SessionStoreError("session_dir_not_directory")


def read_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    entries: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise SessionStoreError("evaluation_entry_invalid")
        entries.append(obj)
    return entries


def write_json(path: Path, obj: Mapping[str, Any], schema_path: Path) -> None:
    validate_json(obj, schema_path)
    path.write_text(canonical_dumps_str(obj), encoding="utf-8")


def append_jsonl(path: Path, obj: Mapping[str, Any], schema_path: Path) -> None:
    validate_json(obj, schema_path)
    payload = canonical_dumps_str(obj)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(payload + "\n")


def load_announce(paths: SessionPaths) -> dict[str, Any]:
    if not paths.announce_path.exists():
        raise SessionStoreError("announce_missing")
    obj = read_json(paths.announce_path)
    if not isinstance(obj, dict):
        raise SessionStoreError("announce_invalid")
    validate_json(obj, ANNOUNCE_SCHEMA)
    return obj


def load_propose(paths: SessionPaths) -> dict[str, Any]:
    if not paths.propose_path.exists():
        raise SessionStoreError("propose_missing")
    obj = read_json(paths.propose_path)
    if not isinstance(obj, dict):
        raise SessionStoreError("propose_invalid")
    validate_json(obj, PROPOSE_SCHEMA)
    return obj


def load_ewl_state(paths: SessionPaths) -> EWLState:
    if not paths.ewl_state_path.exists():
        raise SessionStoreError("ewl_state_missing")
    obj = read_json(paths.ewl_state_path)
    if not isinstance(obj, dict):
        raise SessionStoreError("ewl_state_invalid")
    validate_json(obj, EWL_STATE_SCHEMA)
    return EWLState(
        version=str(obj["version"]),
        wealth=float(obj["wealth"]),
        bankruptcy_floor=float(obj["bankruptcy_floor"]),
        last_increment=float(obj["last_increment"]),
        updates=int(obj["updates"]),
        bankrupt=bool(obj["bankrupt"]),
    )


def load_gate_report(paths: SessionPaths) -> dict[str, Any]:
    if not paths.reality_gate_report_path.exists():
        raise SessionStoreError("gate_report_missing")
    obj = read_json(paths.reality_gate_report_path)
    if not isinstance(obj, dict):
        raise SessionStoreError("gate_report_invalid")
    validate_json(obj, GATE_REPORT_SCHEMA)
    return obj


__all__ = [
    "ANNOUNCE_SCHEMA",
    "CAUSAL_SCHEMA",
    "EVALUATION_SCHEMA",
    "EWL_STATE_SCHEMA",
    "EWL_VERSION",
    "GATE_REPORT_SCHEMA",
    "GATE_REPORT_VERSION",
    "PHYSHIR_SCHEMA",
    "PROPOSE_SCHEMA",
    "SCC_SCHEMA",
    "SCC_VERSION",
    "UVP_VERSION",
    "EWLState",
    "GateReportEntry",
    "SessionPaths",
    "SessionStoreError",
    "append_jsonl",
    "ensure_session_dir",
    "init_session_dir",
    "load_announce",
    "load_ewl_state",
    "load_gate_report",
    "load_propose",
    "read_json",
    "read_jsonl",
    "session_paths",
    "write_json",
]
