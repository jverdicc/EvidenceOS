from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


EVENT_CENSORED = 0
EVENT_PRIMARY = 1
EVENT_COMPETING = 2


@dataclass(frozen=True)
class TrialRow:
    participant_id: str
    arm: str
    duration_days: float
    event_code: int
    covariates: dict[str, Any]
    status: str
    etl_index: int


def _first_non_null(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        cur: Any = payload
        ok = True
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur is not None:
            return cur
    return None


def _event_code(value: Any) -> int:
    if isinstance(value, int) and value in (0, 1, 2):
        return value
    if isinstance(value, str):
        mapping = {
            "censored": EVENT_CENSORED,
            "primary": EVENT_PRIMARY,
            "event": EVENT_PRIMARY,
            "competing": EVENT_COMPETING,
            "competing_event": EVENT_COMPETING,
        }
        v = mapping.get(value.strip().lower())
        if v is not None:
            return v
    raise ValueError(f"invalid event_type/event_code value: {value!r}")


def build_trial_rows(records: list[dict[str, Any]], sessionize: bool = True) -> list[TrialRow]:
    rows: list[TrialRow] = []

    for payload in records:
        participant = _first_non_null(payload, "participant_id", "subject_id", "claim_id_hex")
        arm = _first_non_null(payload, "arm", "trial.arm", "trial_arm_id", "trial.arm_id")
        duration = _first_non_null(
            payload, "duration_days", "time_to_event_days", "followup_days"
        )
        event = _first_non_null(payload, "event_code", "event_type")
        covariates = _first_non_null(payload, "covariates") or {}
        status = _first_non_null(payload, "consort_status", "status") or "randomized"

        if participant is None or arm is None or duration is None or event is None:
            continue

        rows.append(
            TrialRow(
                participant_id=str(participant),
                arm=str(arm),
                duration_days=float(duration),
                event_code=_event_code(event),
                covariates=covariates if isinstance(covariates, dict) else {},
                status=str(status),
                etl_index=int(payload.get("_etl_index", -1)),
            )
        )

    if not sessionize:
        return rows

    by_participant: dict[str, TrialRow] = {}
    for row in sorted(rows, key=lambda r: (r.participant_id, r.etl_index, r.duration_days)):
        by_participant[row.participant_id] = row
    return list(by_participant.values())


def build_trial_dataframe(records: list[dict[str, Any]], sessionize: bool = True):
    try:
        import pandas as pd
    except ModuleNotFoundError as exc:
        raise RuntimeError("pandas is required for build_trial_dataframe") from exc

    rows = build_trial_rows(records, sessionize=sessionize)
    df = pd.DataFrame([asdict(r) for r in rows])
    if df.empty:
        return df

    covariates_df = pd.json_normalize(df["covariates"]).add_prefix("covariate_")
    return pd.concat([df.drop(columns=["covariates"]), covariates_df], axis=1)
