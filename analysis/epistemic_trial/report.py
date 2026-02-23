from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
from lifelines import AalenJohansenFitter, CoxPHFitter, KaplanMeierFitter
from lifelines.utils import restricted_mean_survival_time

from analysis.etl_reader import parse_json_records, read_etl_records
from analysis.epistemic_trial.extract_from_capsules import (
    EVENT_ADVERSARY_SUCCESS,
    EVENT_CENSORED,
    EVENT_FROZEN_CONTAINMENT,
    EVENT_INCIDENT,
    extract_capsule_rows,
)


@dataclass(frozen=True)
class ReportArtifacts:
    km_by_arm_png: str
    km_success_by_arm_png: str
    cif_primary_by_arm_png: str
    cox_summary_csv: str
    rmst_csv: str
    consort_plot: str
    consort_csv: str
    consort_dot: str
    summary_json: str


def _build_dataframe(capsule_rows: list[dict[str, Any]]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for rec in capsule_rows:
        rows.append(
            {
                "time": float(rec["time"]),
                "duration_kbits": float(rec["duration_kbits"]),
                "event_type": int(rec["event_type"]),
                "arm_id": str(rec.get("arm_id") if rec.get("arm_id") is not None else "unassigned"),
                "intervention_id": str(
                    rec.get("intervention_id") if rec.get("intervention_id") is not None else "unassigned"
                ),
                "lane": str(rec.get("lane") if rec.get("lane") is not None else "unknown"),
                "nullspec_id": str(
                    rec.get("nullspec_id") if rec.get("nullspec_id") is not None else "unknown"
                ),
                "adversary_type": str(
                    rec.get("adversary_type") if rec.get("adversary_type") is not None else "unknown"
                ),
                "holdout_ref": str(rec.get("holdout_ref") if rec.get("holdout_ref") is not None else "none"),
                "holdout_bucket": str(rec.get("holdout_bucket") if rec.get("holdout_bucket") is not None else "none"),
                "oracle_id": str(rec.get("oracle_id") if rec.get("oracle_id") is not None else "unknown"),
            }
        )
    return pd.DataFrame(rows)


def _km_outputs(df: pd.DataFrame, out_dir: Path) -> tuple[Path, Path]:
    frozen_png_path = out_dir / "km_by_arm.png"
    success_png_path = out_dir / "km_success_by_arm.png"

    def _plot_for_event(event_code: int, path: Path, title: str) -> None:
        plt.figure(figsize=(8, 5))
        for arm, arm_df in sorted(df.groupby("intervention_id")):
            event_observed = (arm_df["event_type"] == event_code).astype(int)
            kmf = KaplanMeierFitter(label=str(arm))
            kmf.fit(arm_df["time"], event_observed=event_observed)
            kmf.plot_survival_function(ci_show=True)
        plt.title(title)
        plt.xlabel("duration_kbits")
        plt.ylabel("Survival probability")
        plt.grid(True, alpha=0.2)
        plt.tight_layout()
        plt.savefig(path, dpi=180)
        plt.close()

    _plot_for_event(
        EVENT_FROZEN_CONTAINMENT,
        frozen_png_path,
        "Kaplan-Meier by intervention (event = frozen_containment)",
    )
    _plot_for_event(
        EVENT_ADVERSARY_SUCCESS,
        success_png_path,
        "Kaplan-Meier by intervention (event = adversary_success)",
    )
    return frozen_png_path, success_png_path


def _cif_primary_outputs(df: pd.DataFrame, out_dir: Path) -> Path:
    png_path = out_dir / "cif_primary_by_arm.png"

    plt.figure(figsize=(8, 5))
    for arm, arm_df in sorted(df.groupby("intervention_id")):
        ajf = AalenJohansenFitter()
        ajf.fit(
            durations=arm_df["time"],
            event_observed=arm_df["event_type"],
            event_of_interest=EVENT_ADVERSARY_SUCCESS,
            label=str(arm),
        )
        cif = ajf.cumulative_density_.copy()
        cif.columns = [str(arm)]
        cif.plot(drawstyle="steps-post")

    plt.title("Cumulative incidence by intervention (primary = adversary_success)")
    plt.xlabel("duration_kbits")
    plt.ylabel("Cumulative incidence")
    plt.ylim(0, 1)
    plt.grid(True, alpha=0.2)
    plt.tight_layout()
    plt.savefig(png_path, dpi=180)
    plt.close()
    return png_path


def _cox_outputs(df: pd.DataFrame, out_dir: Path) -> Path:
    summary_csv = out_dir / "cox_summary.csv"
    covariates = [
        "arm_id",
        "intervention_id",
        "lane",
        "oracle_id",
        "nullspec_id",
        "adversary_type",
        "holdout_ref",
        "holdout_bucket",
    ]

    all_rows: list[pd.DataFrame] = []
    for cause, cause_name in (
        (EVENT_ADVERSARY_SUCCESS, "adversary_success"),
        (EVENT_FROZEN_CONTAINMENT, "frozen_containment"),
        (EVENT_INCIDENT, "incident"),
    ):
        model_df = df[["time", "event_type", *covariates]].copy()
        model_df["event"] = (model_df["event_type"] == cause).astype(int)
        model_df = model_df.drop(columns=["event_type"])
        if model_df["event"].sum() == 0:
            all_rows.append(pd.DataFrame([{"cause": cause_name, "warning": "no_events_for_cause"}]))
            continue

        model_df = pd.get_dummies(model_df, columns=covariates, drop_first=True)
        low_var_cols = [c for c in model_df.columns if c not in {"time", "event"} and model_df[c].nunique() <= 1]
        model_df = model_df.drop(columns=low_var_cols)

        try:
            cph = CoxPHFitter(penalizer=0.01)
            cph.fit(model_df, duration_col="time", event_col="event")
            summary = cph.summary.reset_index().rename(columns={"index": "covariate"})
            summary.insert(0, "cause", cause_name)
            all_rows.append(summary)
        except Exception as exc:
            all_rows.append(pd.DataFrame([{"cause": cause_name, "warning": f"cox_fit_failed: {exc}"}]))

    pd.concat(all_rows, ignore_index=True).to_csv(summary_csv, index=False)
    return summary_csv


def _rmst_outputs(df: pd.DataFrame, out_dir: Path) -> Path:
    rmst_csv = out_dir / "rmst_by_arm.csv"
    horizon_kbits = float(df["time"].quantile(0.9)) if len(df) > 2 else float(df["time"].max())
    if horizon_kbits <= 0:
        horizon_kbits = 1.0

    rows: list[dict[str, Any]] = []
    for arm, arm_df in sorted(df.groupby("intervention_id")):
        kmf = KaplanMeierFitter().fit(
            arm_df["time"],
            event_observed=(arm_df["event_type"] == EVENT_ADVERSARY_SUCCESS).astype(int),
        )
        rmst_value = restricted_mean_survival_time(kmf, t=horizon_kbits)
        rows.append(
            {
                "intervention_id": arm,
                "horizon_kbits": horizon_kbits,
                "rmst_kbits": float(rmst_value),
                "n": int(len(arm_df)),
                "endpoint": "adversary_success",
            }
        )

    pd.DataFrame(rows).to_csv(rmst_csv, index=False)
    return rmst_csv


def _consort_outputs(records: list[dict[str, Any]], capsule_rows: list[dict[str, Any]], out_dir: Path) -> tuple[Path, Path, Path]:
    consort_csv = out_dir / "consort_flow.csv"
    consort_png = out_dir / "consort_flow.png"
    consort_dot = out_dir / "consort_flow.dot"

    preflight = [r for r in records if "preflight" in str(r.get("schema", "")).lower()]
    randomized = [r for r in capsule_rows if r.get("arm_id") is not None or r.get("intervention_id") is not None]
    event_counts = {
        "censored": sum(int(r.get("event_type", EVENT_CENSORED)) == EVENT_CENSORED for r in capsule_rows),
        "adversary_success": sum(int(r.get("event_type", EVENT_CENSORED)) == EVENT_ADVERSARY_SUCCESS for r in capsule_rows),
        "frozen_containment": sum(int(r.get("event_type", EVENT_CENSORED)) == EVENT_FROZEN_CONTAINMENT for r in capsule_rows),
        "incident": sum(int(r.get("event_type", EVENT_CENSORED)) == EVENT_INCIDENT for r in capsule_rows),
    }

    rows = [
        {"stage": "etl_records", "count": len(records)},
        {"stage": "preflight_records", "count": len(preflight)},
        {"stage": "claim_capsules", "count": len(capsule_rows)},
        {"stage": "randomized", "count": len(randomized)},
        {"stage": "event_adversary_success", "count": event_counts["adversary_success"]},
        {"stage": "event_frozen_containment", "count": event_counts["frozen_containment"]},
        {"stage": "event_incident", "count": event_counts["incident"]},
        {"stage": "event_censored", "count": event_counts["censored"]},
    ]
    pd.DataFrame(rows).to_csv(consort_csv, index=False)

    dot_lines = ["digraph consort {", "  rankdir=TB;"]
    for row in rows:
        dot_lines.append(f"  {row['stage']} [label=\"{row['stage']}\\nn={row['count']}\"];")
    for src, dst in zip(rows, rows[1:]):
        dot_lines.append(f"  {src['stage']} -> {dst['stage']};")
    dot_lines.append("}")
    consort_dot.write_text("\n".join(dot_lines) + "\n", encoding="utf-8")

    plt.figure(figsize=(8, 5))
    y = list(reversed(range(len(rows))))
    for i, row in enumerate(rows):
        plt.text(0.1, y[i], f"{row['stage']}: n={row['count']}", fontsize=10, va="center")
        if i < len(rows) - 1:
            plt.annotate("", xy=(0.08, y[i + 1] + 0.2), xytext=(0.08, y[i] - 0.2), arrowprops=dict(arrowstyle="->", lw=1.5))
    plt.xlim(0, 1)
    plt.ylim(-0.5, len(rows) - 0.5)
    plt.axis("off")
    plt.title("CONSORT-style trial flow")
    plt.tight_layout()
    plt.savefig(consort_png, dpi=180)
    plt.close()

    return consort_png, consort_csv, consort_dot


def generate_report(etl_path: Path, out_dir: Path) -> ReportArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = parse_json_records(read_etl_records(etl_path))
    capsule_rows = extract_capsule_rows(records)
    if not capsule_rows:
        raise ValueError("No ClaimCapsule records found in ETL")

    df = _build_dataframe(capsule_rows)
    km_by_arm_png, km_success_by_arm_png = _km_outputs(df, out_dir)
    cif_primary_png = _cif_primary_outputs(df, out_dir)
    cox_summary_csv = _cox_outputs(df, out_dir)
    rmst_csv = _rmst_outputs(df, out_dir)
    consort_plot, consort_csv, consort_dot = _consort_outputs(records, capsule_rows, out_dir)

    summary = {
        "etl_path": str(etl_path),
        "records": int(len(records)),
        "capsules": int(len(capsule_rows)),
        "arms": sorted(str(v) for v in df["intervention_id"].unique().tolist()),
        "time_unit": "kbits",
        "event_types": {
            "0": "censored",
            "1": "adversary_success",
            "2": "frozen_containment",
            "3": "incident",
        },
        "artifacts": asdict(
            ReportArtifacts(
                km_by_arm_png=km_by_arm_png.name,
                km_success_by_arm_png=km_success_by_arm_png.name,
                cif_primary_by_arm_png=cif_primary_png.name,
                cox_summary_csv=cox_summary_csv.name,
                rmst_csv=rmst_csv.name,
                consort_plot=consort_plot.name,
                consort_csv=consort_csv.name,
                consort_dot=consort_dot.name,
                summary_json="summary.json",
            )
        ),
    }
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return ReportArtifacts(
        km_by_arm_png=str(km_by_arm_png),
        km_success_by_arm_png=str(km_success_by_arm_png),
        cif_primary_by_arm_png=str(cif_primary_png),
        cox_summary_csv=str(cox_summary_csv),
        rmst_csv=str(rmst_csv),
        consort_plot=str(consort_plot),
        consort_csv=str(consort_csv),
        consort_dot=str(consort_dot),
        summary_json=str(summary_path),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate end-to-end trial report from ClaimCapsule ETL")
    parser.add_argument("--etl", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    artifacts = generate_report(args.etl, args.out)
    print(json.dumps(asdict(artifacts), indent=2))


if __name__ == "__main__":
    main()
