from __future__ import annotations

import argparse
from pathlib import Path

from analysis.consort import write_consort_diagram
from analysis.etl_reader import parse_json_records, read_etl_records
from analysis.trial_dataframe import EVENT_COMPETING, EVENT_PRIMARY, build_trial_dataframe


def _require_analysis_dependencies():
    try:
        import matplotlib.pyplot as plt
        import numpy as np
        import pandas as pd
        from lifelines import AalenJohansenFitter, CoxPHFitter, KaplanMeierFitter
    except ModuleNotFoundError as exc:
        missing = exc.name or "required dependency"
        raise RuntimeError(
            "Missing analysis dependency: "
            f"{missing}. Install with `python -m pip install -e '.[analysis]'`."
        ) from exc

    return {
        "plt": plt,
        "np": np,
        "pd": pd,
        "AalenJohansenFitter": AalenJohansenFitter,
        "CoxPHFitter": CoxPHFitter,
        "KaplanMeierFitter": KaplanMeierFitter,
    }


def _numeric_covariates(df, pd):
    cols = [c for c in df.columns if c.startswith("covariate_")]
    keep: list[str] = []
    for col in cols:
        if pd.api.types.is_numeric_dtype(df[col]):
            keep.append(col)
    return keep


def write_km_curves(df, out_dir: Path, deps) -> None:
    plt = deps["plt"]
    KaplanMeierFitter = deps["KaplanMeierFitter"]
    AalenJohansenFitter = deps["AalenJohansenFitter"]

    km = KaplanMeierFitter()
    fig, ax = plt.subplots(figsize=(7, 5))
    for arm, grp in df.groupby("arm"):
        km.fit(
            durations=grp["duration_days"],
            event_observed=(grp["event_code"] > 0).astype(int),
            label=f"arm={arm}",
        )
        km.plot_survival_function(ax=ax)
    ax.set_title("Kaplan–Meier (all-cause failure)")
    ax.set_xlabel("Days")
    ax.set_ylabel("Survival probability")
    fig.tight_layout()
    fig.savefig(out_dir / "km_by_arm.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 5))
    for arm, grp in df.groupby("arm"):
        aj = AalenJohansenFitter()
        aj.fit(
            grp["duration_days"],
            grp["event_code"],
            event_of_interest=EVENT_PRIMARY,
            label=f"arm={arm}",
        )
        aj.plot(ax=ax)
    ax.set_title("Cumulative incidence (primary event with competing risks)")
    ax.set_xlabel("Days")
    ax.set_ylabel("Cumulative incidence")
    fig.tight_layout()
    fig.savefig(out_dir / "cif_primary_by_arm.png", dpi=150)
    plt.close(fig)


def _fit_cause_specific(df, event_code: int, covariates: list[str], deps):
    pd = deps["pd"]
    CoxPHFitter = deps["CoxPHFitter"]

    work = df[["duration_days", "event_code", "arm", *covariates]].copy()
    work["event_observed"] = (work["event_code"] == event_code).astype(int)
    work = work.drop(columns=["event_code"])
    work = pd.get_dummies(work, columns=["arm"], drop_first=True)

    cph = CoxPHFitter()
    cph.fit(work, duration_col="duration_days", event_col="event_observed")
    out = cph.summary.reset_index().rename(columns={"index": "term"})
    out.insert(0, "cause", "primary" if event_code == EVENT_PRIMARY else "competing")
    return out


def covariate_balance_table(df, deps):
    pd = deps["pd"]
    np = deps["np"]

    covariates = [c for c in df.columns if c.startswith("covariate_")]
    if not covariates:
        return pd.DataFrame(columns=["arm", "covariate", "mean", "std", "n"])

    pieces = []
    for arm, grp in df.groupby("arm"):
        for cov in covariates:
            s = pd.to_numeric(grp[cov], errors="coerce")
            pieces.append(
                {
                    "arm": arm,
                    "covariate": cov,
                    "mean": float(np.nanmean(s)),
                    "std": float(np.nanstd(s, ddof=1)) if s.notna().sum() > 1 else np.nan,
                    "n": int(s.notna().sum()),
                }
            )
    return pd.DataFrame(pieces)


def run(etl_path: str, out_dir: str) -> None:
    deps = _require_analysis_dependencies()
    pd = deps["pd"]

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    records = parse_json_records(read_etl_records(etl_path))
    df = build_trial_dataframe(records)
    if df.empty:
        raise ValueError("No trial records found in ETL")

    write_km_curves(df, out, deps)

    covariates = _numeric_covariates(df, pd)
    cox_primary = _fit_cause_specific(df, EVENT_PRIMARY, covariates, deps)
    cox_competing = _fit_cause_specific(df, EVENT_COMPETING, covariates, deps)
    cox_summary = pd.concat([cox_primary, cox_competing], ignore_index=True)
    cox_summary.to_csv(out / "cox_summary.csv", index=False)

    balance = covariate_balance_table(df, deps)
    balance.to_csv(out / "covariate_balance.csv", index=False)

    write_consort_diagram(df, out)


def main() -> None:
    parser = argparse.ArgumentParser(description="DiscOS trial survival analysis")
    parser.add_argument("--etl", required=True, help="Path to ETL log")
    parser.add_argument("--out", required=True, help="Output directory for analysis artifacts")
    args = parser.parse_args()
    run(args.etl, args.out)


if __name__ == "__main__":
    main()
