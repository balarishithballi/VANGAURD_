#!/usr/bin/env python3
"""
explain_event_shap.py

Compute SHAP values for CatBoost model for a set of events or a single event.

Usage:
  python3 explain_event_shap.py --event-index 123
  python3 explain_event_shap.py --sample 1000 --out shap_sample.parquet

Outputs:
 - prints top contributing features for the event(s)
 - writes shap values to file (optional)
"""

import os, json, joblib, argparse
import numpy as np, pandas as pd
from catboost import CatBoostClassifier, Pool
import shap
import warnings
warnings.filterwarnings("ignore")

MODEL_PATH = "output/catboost_classifier.cbm"
SCALER_PATH = "output/scaler.pkl"
AUG_CSV = "output/features_timeaware_augmented_catboost.csv"
SHAP_CACHE = "output/shap_cache.parquet"

NUMERIC_COLS = [
    "category_id","sub_category_id","severity_id","location_id_num",
    "is_threat","is_ueba","is_vuln","hour_of_day","day_of_week",
    "is_weekend","is_off_hours","event_count"
]

def load_model_and_data():
    if not os.path.exists(MODEL_PATH):
        raise SystemExit("Model missing: " + MODEL_PATH)
    model = CatBoostClassifier()
    model.load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
    df = pd.read_csv(AUG_CSV, low_memory=False)
    # ensure numeric cols
    for c in NUMERIC_COLS:
        if c not in df.columns:
            df[c] = 0
    X = df[NUMERIC_COLS].fillna(0).astype(float).to_numpy()
    if scaler is not None:
        Xs = scaler.transform(X)
    else:
        Xs = X
    return model, scaler, df, Xs

def compute_shap_for_indices(indices, model, Xs, df):
    # Use TreeExplainer for CatBoost
    explainer = shap.TreeExplainer(model)
    X_sel = Xs[indices]
    shap_values = explainer.shap_values(X_sel)
    # shap_values shape: (n_samples, n_features) for binary catboost -> list? CatBoost returns array
    # Return dataframe with per-feature shap for each sample
    feature_names = NUMERIC_COLS
    if isinstance(shap_values, list):
        # multiclass returns list; for binary it might be 2 arrays. take positive class index 1
        shap_arr = np.array(shap_values[-1])
    else:
        shap_arr = np.array(shap_values)
    out = []
    for i, idx in enumerate(indices):
        row = {"event_index": int(idx)}
        # per-feature
        for j, fn in enumerate(feature_names):
            row[f"shap_{fn}"] = float(shap_arr[i,j])
        # add base value and model prob
        row["base_value"] = float(explainer.expected_value)
        row["pred_prob"] = float(model.predict_proba(X_sel[i].reshape(1,-1))[:,1])
        out.append(row)
    return pd.DataFrame(out)

def pretty_print_shap_row(shap_row):
    # show top 8 features by absolute contribution
    feats = {k:v for k,v in shap_row.items() if k.startswith("shap_")}
    sorted_feats = sorted(feats.items(), key=lambda x: abs(x[1]), reverse=True)[:8]
    print("Top contributors:")
    for k,v in sorted_feats:
        print(f"  {k.replace('shap_','')}: {v:+.4f}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-index", type=int, help="single event index (matching augmented CSV)")
    parser.add_argument("--sample", type=int, default=0, help="sample N events to compute SHAP for")
    parser.add_argument("--out", help="optional output file to save shap rows (parquet/csv)")
    args = parser.parse_args()

    model, scaler, df, Xs = load_model_and_data()
    n = len(df)
    if args.event_index is not None:
        idx = args.event_index
        if idx < 0 or idx >= n:
            raise SystemExit("index out of range")
        df_shap = compute_shap_for_indices([idx], model, Xs, df)
        print("Event index:", idx)
        print("raw:", df.at[idx,"raw"] if "raw" in df.columns else "")
        pretty_print_shap_row(df_shap.iloc[0].to_dict())
        if args.out:
            df_shap.to_parquet(args.out) if args.out.endswith(".parquet") else df_shap.to_csv(args.out, index=False)
            print("Saved shap to", args.out)
        return

    if args.sample and args.sample>0:
        sample_n = min(args.sample, n)
        indices = list(df.sample(sample_n, random_state=42).index)
        df_shap = compute_shap_for_indices(indices, model, Xs, df)
        if args.out:
            df_shap.to_parquet(args.out) if args.out.endswith(".parquet") else df_shap.to_csv(args.out, index=False)
            print("Saved shap to", args.out)
        else:
            print(df_shap.head())
        return

    print("No args provided; run with --event-index IDX or --sample N")
    return

if __name__ == "__main__":
    main()
