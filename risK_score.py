#!/usr/bin/env python3
"""
risk_score.py

Compute a unified risk score per event and append to augmented CSV.

Inputs:
 - output/features_timeaware_augmented_catboost.csv  (created by CatBoost retrain)
 - output/catboost_classifier.cbm
 - output/isolation_forest.joblib
 - output/scaler.pkl
 - threat_patterns.json

Outputs:
 - output/features_timeaware_augmented_catboost_with_risk.csv
 - returns DataFrame (also accessible via import)

Scoring heuristic (configurable):
 - model_prob (CatBoost) weight = 0.50
 - normalized_ueba_score weight = 0.30
 - threat_intel_match weight = 0.15
 - vuln/lateral keyword boost weight = 0.05

Score in range [0,100]
"""

import os, json, re, joblib, argparse
import numpy as np
import pandas as pd
from catboost import CatBoostClassifier

# ---------- Config ----------
AUG_CSV = "output/features_timeaware_augmented_catboost.csv"
OUT_CSV = "output/features_timeaware_augmented_catboost_with_risk.csv"
MODEL_PATH = "output/catboost_classifier.cbm"
UEBA_PATH = "output/isolation_forest.joblib"
SCALER_PATH = "output/scaler.pkl"
PATTERN_FILE = "threat_patterns.json"

WEIGHTS = {
    "model_prob": 0.50,
    "ueba": 0.30,
    "ti_match": 0.15,
    "vuln_lateral_boost": 0.05
}

# ---------- Helpers ----------
def load_patterns(path=PATTERN_FILE):
    if not os.path.exists(path):
        return {"known_threats":{}, "vulnerabilities":{}, "ueba_signals":{}}
    return json.load(open(path,"r",encoding="utf-8"))

def regex_any_list(patterns, text):
    if text is None: return False
    s = str(text)
    for p in patterns:
        try:
            if re.search(p, s, flags=re.IGNORECASE):
                return True
        except:
            continue
    return False

def normalize_arr(a):
    # min-max normalize to 0..1, safe for constant arrays
    a = np.asarray(a, dtype=float)
    mn = np.nanmin(a)
    mx = np.nanmax(a)
    if np.isfinite(mn) and np.isfinite(mx) and mx>mn:
        return (a - mn) / (mx - mn)
    else:
        return np.zeros_like(a, dtype=float)

# ---------- Core ----------
def compute_risk(df):
    # load artifacts
    model = CatBoostClassifier()
    if os.path.exists(MODEL_PATH):
        model.load_model(MODEL_PATH)
    else:
        model = None

    scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None
    iso = joblib.load(UEBA_PATH) if os.path.exists(UEBA_PATH) else None
    patterns = load_patterns(PATTERN_FILE)
    ti_flat = [p for v in patterns.get("known_threats",{}).values() for p in v]
    vuln_flat = [p for v in patterns.get("vulnerabilities",{}).values() for p in v]
    lateral_regex = [r"psexec", r"wmic", r"smbclient", r"rpcclient", r"pass the hash", r"rdesktop"]

    # model probability
    if model is not None:
        # make sure we have numeric features used during training
        # we expect 'predicted_prob' may already be present; prefer that
        if "predicted_prob" in df.columns and df["predicted_prob"].notna().all():
            model_prob = df["predicted_prob"].fillna(0).astype(float).to_numpy()
        else:
            # fallback: compute from numeric columns if present
            numeric_cols = ["category_id","sub_category_id","severity_id","location_id_num",
                            "is_threat","is_ueba","is_vuln","hour_of_day","day_of_week",
                            "is_weekend","is_off_hours","event_count"]
            X = df[numeric_cols].fillna(0).astype(float).to_numpy()
            if scaler is not None:
                X = scaler.transform(X)
            try:
                model_prob = model.predict_proba(X)[:,1]
            except Exception:
                # model fallback: binary predict -> 1.0 or 0.0
                model_prob = model.predict(X).astype(float)
    else:
        model_prob = np.zeros(len(df), dtype=float)

    # UEBA normalized (decision_function -> larger = more normal typically; but for IsolationForest higher = less anomaly, depends)
    # cat decision_function: higher = more normal; in many libs IsolationForest.decision_function yields larger better.
    if iso is not None:
        numeric_cols = ["category_id","sub_category_id","severity_id","location_id_num",
                        "is_threat","is_ueba","is_vuln","hour_of_day","day_of_week",
                        "is_weekend","is_off_hours","event_count"]
        X_full = df[numeric_cols].fillna(0).astype(float).to_numpy()
        if scaler is not None:
            X_full = scaler.transform(X_full)
        try:
            u_scores = iso.decision_function(X_full)  # larger=normal for sklearn: decision_function -> bigger is less abnormal
            # Convert to anomaly magnitude: anomaly_score = -u_scores
            u_score_norm = normalize_arr(-u_scores)
        except Exception:
            u_score_norm = np.zeros(len(df), dtype=float)
    else:
        u_score_norm = np.zeros(len(df), dtype=float)

    # Threat intel match boolean
    ti_matches = df["raw"].apply(lambda r: regex_any_list(ti_flat, r)).astype(int).to_numpy()

    # vulnerability or lateral boost
    vuln_mask = df["raw"].apply(lambda r: regex_any_list(vuln_flat, r)).astype(int).to_numpy()
    lateral_mask = df["raw"].apply(lambda r: regex_any_list(lateral_regex, r)).astype(int).to_numpy()
    vuln_lateral_boost = np.clip(vuln_mask + lateral_mask, 0, 1)  # 0 or 1

    # normalize model_prob to 0..1 (CatBoost prob already 0..1)
    model_prob_norm = np.clip(model_prob.astype(float), 0.0, 1.0)

    # final linear weighted score
    score = (
        WEIGHTS["model_prob"] * model_prob_norm +
        WEIGHTS["ueba"] * u_score_norm +
        WEIGHTS["ti_match"] * ti_matches +
        WEIGHTS["vuln_lateral_boost"] * vuln_lateral_boost
    )

    # scale to 0..100
    score_0_1 = normalize_arr(score)
    score_0_100 = (score_0_1 * 100.0).round(2)

    df["risk_score"] = score_0_100
    # helpful breakdown columns for dashboard
    df["risk_model_prob"] = (model_prob_norm * 100).round(3)
    df["risk_ueba_norm"] = (u_score_norm * 100).round(3)
    df["risk_ti_match"] = ti_matches
    df["risk_vuln_lateral"] = vuln_lateral_boost

    return df

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Compute risk score for augmented CSV")
    parser.add_argument("--in", dest="infile", default=AUG_CSV)
    parser.add_argument("--out", dest="outfile", default=OUT_CSV)
    args = parser.parse_args()

    infile = args.infile
    outfile = args.outfile
    if not os.path.exists(infile):
        raise SystemExit(f"{infile} missing. Run CatBoost pipeline first.")

    df = pd.read_csv(infile, low_memory=False)
    df = compute_risk(df)
    df.to_csv(outfile, index=False)
    print("Saved with risk scores to", outfile)

if __name__ == "__main__":
    import argparse
    main()
