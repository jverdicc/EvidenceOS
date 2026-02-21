from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd
from lifelines import CoxPHFitter, KaplanMeierFitter
from lifelines.statistics import proportional_hazard_test
from lifelines.utils import restricted_mean_survival_time

from analysis.etl_reader import parse_json_records, read_etl_records
from analysis.epistemic_trial.extract_from_capsules import extract_capsule_rows


@dataclass(frozen=True)
class ReportArtifacts:
    km_plot: str
    km_csv: str
    cox_summary_csv: str
    cox_ph_assumption_csv: str
    rmst_csv: str
    holm_csv: str
    consort_plot: str
    consort_csv: str
    summary_json: str


def _build_dataframe(capsule_rows: list[dict[str, Any]]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for rec in capsule_rows:
        rows.append(
            {
                "time": float(rec["k_bits_total"]),
                "event": int(rec["frozen_event"]),
                "censor": int(rec["censored"]),
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
            }
        )
    return pd.DataFrame(rows)


def _km_outputs(df: pd.DataFrame, out_dir: Path) -> tuple[Path, Path]:
    png_path = out_dir / "km_curves.png"
    csv_path = out_dir / "km_curves.csv"

    plt.figure(figsize=(8, 5))
    curve_rows: list[dict[str, Any]] = []
    for arm, arm_df in sorted(df.groupby("intervention_id")):
        kmf = KaplanMeierFitter(label=str(arm))
        kmf.fit(arm_df["time"], event_observed=arm_df["event"])
        kmf.plot_survival_function(ci_show=True)

        surv = kmf.survival_function_.reset_index()
        ci = kmf.confidence_interval_survival_function_.reset_index()
        ci_cols = [c for c in ci.columns if c != "index"]
        lo_col, hi_col = ci_cols[0], ci_cols[1]

        for idx, rec in surv.iterrows():
            curve_rows.append(
                {
                    "intervention_id": arm,
                    "timeline": float(rec["timeline"]),
                    "survival": float(rec[str(arm)]),
                    "ci_lower": float(ci.iloc[idx][lo_col]),
                    "ci_upper": float(ci.iloc[idx][hi_col]),
                }
            )

    plt.title("Kaplan-Meier by intervention")
    plt.xlabel("k_bits_total")
    plt.ylabel("Survival probability")
    plt.grid(True, alpha=0.2)
    plt.tight_layout()
    plt.savefig(png_path, dpi=180)
    plt.close()

    pd.DataFrame(curve_rows).to_csv(csv_path, index=False)
    return png_path, csv_path


def _cox_outputs(df: pd.DataFrame, out_dir: Path) -> tuple[Path, Path]:
    summary_csv = out_dir / "cox_summary.csv"
    ph_csv = out_dir / "cox_ph_assumption.csv"

    model_df = pd.get_dummies(
        df[["time", "event", "arm_id", "intervention_id", "lane", "nullspec_id", "adversary_type", "holdout_ref"]],
        columns=["arm_id", "intervention_id", "lane", "nullspec_id", "adversary_type", "holdout_ref"],
        drop_first=True,
    )

    if "event" not in model_df or model_df["event"].nunique() < 2:
        pd.DataFrame([{"warning": "insufficient event variance for Cox PH"}]).to_csv(summary_csv, index=False)
        pd.DataFrame([{"warning": "insufficient event variance for PH test"}]).to_csv(ph_csv, index=False)
        return summary_csv, ph_csv

    low_var_cols = [c for c in model_df.columns if c not in {"time", "event"} and model_df[c].nunique() <= 1]
    model_df = model_df.drop(columns=low_var_cols)

    try:
        cph = CoxPHFitter(penalizer=0.01)
        cph.fit(model_df, duration_col="time", event_col="event")
        cph.summary.to_csv(summary_csv)

        ph_test = proportional_hazard_test(cph, model_df, time_transform="rank")
        ph_test.summary.to_csv(ph_csv)
    except Exception as exc:
        pd.DataFrame([{"warning": f"cox_fit_failed: {exc}"}]).to_csv(summary_csv, index=False)
        pd.DataFrame([{"warning": f"ph_test_failed: {exc}"}]).to_csv(ph_csv, index=False)
    return summary_csv, ph_csv


def _rmst_outputs(df: pd.DataFrame, out_dir: Path) -> Path:
    rmst_csv = out_dir / "rmst_by_arm.csv"
    horizon = float(df["time"].quantile(0.9)) if len(df) > 2 else float(df["time"].max())
    if horizon <= 0:
        horizon = 1.0

    rows: list[dict[str, Any]] = []
    for arm, arm_df in sorted(df.groupby("intervention_id")):
        kmf = KaplanMeierFitter().fit(arm_df["time"], event_observed=arm_df["event"])
        rmst_value = restricted_mean_survival_time(kmf, t=horizon)
        rows.append({"intervention_id": arm, "horizon": horizon, "rmst": float(rmst_value), "n": int(len(arm_df))})

    pd.DataFrame(rows).to_csv(rmst_csv, index=False)
    return rmst_csv


def _holm_bonferroni_outputs(df: pd.DataFrame, out_dir: Path, alpha: float = 0.05) -> Path:
    from scipy.stats import fisher_exact

    holm_csv = out_dir / "nullspec_holm_bonferroni.csv"

    rows: list[dict[str, Any]] = []
    for nullspec, group in df.groupby("nullspec_id"):
        other = df[df["nullspec_id"] != nullspec]
        if other.empty:
            pvalue = 1.0
            odds_ratio = 1.0
        else:
            table = [
                [int(group["event"].sum()), int(len(group) - group["event"].sum())],
                [int(other["event"].sum()), int(len(other) - other["event"].sum())],
            ]
            odds_ratio, pvalue = fisher_exact(table, alternative="two-sided")
        rows.append(
            {
                "nullspec_id": nullspec,
                "n": int(len(group)),
                "events": int(group["event"].sum()),
                "event_rate": float(group["event"].mean()),
                "odds_ratio": float(odds_ratio),
                "p_value": float(pvalue),
            }
        )

    ranked = sorted(rows, key=lambda r: r["p_value"])
    m = len(ranked)
    for i, rec in enumerate(ranked, start=1):
        threshold = alpha / (m - i + 1)
        rec["holm_threshold"] = threshold
        rec["reject_h0"] = bool(rec["p_value"] <= threshold)
    pd.DataFrame(ranked).to_csv(holm_csv, index=False)
    return holm_csv


def _consort_outputs(records: list[dict[str, Any]], capsule_rows: list[dict[str, Any]], out_dir: Path) -> tuple[Path, Path]:
    consort_csv = out_dir / "consort_flow.csv"
    consort_png = out_dir / "consort_flow.png"

    preflight = [r for r in records if "preflight" in str(r.get("schema", "")).lower()]
    randomized = [r for r in capsule_rows if r.get("arm_id") is not None or r.get("intervention_id") is not None]
    frozen = [r for r in capsule_rows if int(r.get("frozen_event", 0)) == 1]
    censored = [r for r in capsule_rows if int(r.get("censored", 0)) == 1]

    rows = [
        {"stage": "etl_records", "count": len(records)},
        {"stage": "preflight_records", "count": len(preflight)},
        {"stage": "claim_capsules", "count": len(capsule_rows)},
        {"stage": "randomized", "count": len(randomized)},
        {"stage": "frozen_event", "count": len(frozen)},
        {"stage": "censored", "count": len(censored)},
    ]
    pd.DataFrame(rows).to_csv(consort_csv, index=False)

    plt.figure(figsize=(8, 4))
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

    return consort_png, consort_csv


def generate_report(etl_path: Path, out_dir: Path) -> ReportArtifacts:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = parse_json_records(read_etl_records(etl_path))
    capsule_rows = extract_capsule_rows(records)
    if not capsule_rows:
        raise ValueError("No ClaimCapsule records found in ETL")

    df = _build_dataframe(capsule_rows)
    km_plot, km_csv = _km_outputs(df, out_dir)
    cox_summary_csv, cox_ph_csv = _cox_outputs(df, out_dir)
    rmst_csv = _rmst_outputs(df, out_dir)
    holm_csv = _holm_bonferroni_outputs(df, out_dir)
    consort_plot, consort_csv = _consort_outputs(records, capsule_rows, out_dir)

    summary = {
        "etl_path": str(etl_path),
        "records": int(len(records)),
        "capsules": int(len(capsule_rows)),
        "arms": sorted(str(v) for v in df["intervention_id"].unique().tolist()),
        "artifacts": asdict(
            ReportArtifacts(
                km_plot=km_plot.name,
                km_csv=km_csv.name,
                cox_summary_csv=cox_summary_csv.name,
                cox_ph_assumption_csv=cox_ph_csv.name,
                rmst_csv=rmst_csv.name,
                holm_csv=holm_csv.name,
                consort_plot=consort_plot.name,
                consort_csv=consort_csv.name,
                summary_json="summary.json",
            )
        ),
    }
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return ReportArtifacts(
        km_plot=str(km_plot),
        km_csv=str(km_csv),
        cox_summary_csv=str(cox_summary_csv),
        cox_ph_assumption_csv=str(cox_ph_csv),
        rmst_csv=str(rmst_csv),
        holm_csv=str(holm_csv),
        consort_plot=str(consort_plot),
        consort_csv=str(consort_csv),
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
