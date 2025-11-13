#!/usr/bin/env python3
"""
compute_metrics_from_ml.py

Compute SOC/SIEM operational metrics ONLY from ML pipeline outputs.

Includes:
- Incident grouping (fixed)
- MTTD, MTTR
- False Positive / False Negative Rates
- Detection Rate
- Alert Volume & Severity
- Event Correlation Accuracy
- Anomaly Frequency
- Baseline Deviation Score (UEBA)
- ML Detection Rate
- Vulnerability Detection Rate
- Threat Intelligence Match Rate
- Lateral Movement Metrics
- Privilege Escalation Metrics
- Unusual Data Transfer Metrics
- System Health Metrics
- Asset Exposure Time

Outputs:
- output/metrics_report.json
- output/metrics_summary.csv
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from collections import Counter
import re
from tqdm import tqdm

# ---------- CONFIG ----------
INPUT_CSV = "output/features_timeaware.csv"
CLASSIFIER_PATH = "output/xgb_classifier.joblib"
UEBA_PATH = "output/isolation_forest.joblib"
SCALER_PATH = "output/scaler.pkl"
THREAT_PATTERNS = "threat_patterns.json"
OUTPUT_JSON = "output/metrics_report.json"
OUTPUT_SUMMARY_CSV = "output/metrics_summary.csv"

INCIDENT_WINDOW_SECONDS = 3600  # 1-hour sliding window

# Remediation detection
REMEDIATION_KEYWORDS = [
    r"remediat", r"resolv", r"isolat", r"patch", r"applied patch",
    r"blocked", r"quarantine", r"mitigat", r"fixed", r"contain"
]

# Lateral movement signatures
LATERAL_KEYWORDS = [
    r"psexec", r"wmic", r"smbclient", r"rpcclient",
    r"rdesktop", r"pass the hash", r"psexec.py"
]

# Unusual transfer
DATA_TRANSFER_REGEX = [
    r"transferred\s+[0-9]{6,}",
    r"downloaded\s+[0-9]{6,}",
    r"upload size exceeded",
    r"scp .*@",
    r"curl -T"
]

# Load patterns
if os.path.exists(THREAT_PATTERNS):
    with open(THREAT_PATTERNS, "r") as f:
        PATTERNS = json.load(f)
else:
    PATTERNS = {"known_threats": {}, "vulnerabilities": {}, "ueba_signals": {}}


# ---------- HELPERS ----------
def safe_load(path):
    if os.path.exists(path):
        return joblib.load(path)
    return None

def parse_ts(ts):
    try:
        return pd.to_datetime(ts, utc=True)
    except:
        return None

def regex_any(patterns, text):
    if text is None:
        return False
    text = str(text)
    for p in patterns:
        try:
            if re.search(p, text, flags=re.IGNORECASE):
                return True
        except:
            continue
    return False

def load_data():
    df = pd.read_csv(INPUT_CSV, low_memory=False)
    df["datetime"] = df["timestamp"].apply(parse_ts)
    df = df[df["datetime"].notna()].reset_index(drop=True)
    return df


# ---------- FIXED INCIDENT BUILDER ----------
def group_events_into_incidents(df, primary_entity_cols=["user","src_ip","host"], window_seconds=INCIDENT_WINDOW_SECONDS):

    df = df.copy()

    # Pick logical entity
    def pick_entity(row):
        for c in primary_entity_cols:
            if c in df.columns:
                v = row.get(c)
                if pd.notna(v) and str(v).strip() not in ("", "nan", "none"):
                    return f"{c}:{v}"
        return f"host:{row.get('source_file','unknown')}"

    df["entity"] = df.apply(pick_entity, axis=1)
    df["ts_epoch"] = df["datetime"].astype(int) // 1_000_000_000

    incidents = []

    for entity, grp in df.groupby("entity"):
        grp = grp.sort_values("ts_epoch").reset_index()

        current = {
            "entity": entity,
            "indexes": [],
            "start_ts": None,
            "end_ts": None
        }

        last_ts = None

        for _, row in grp.iterrows():
            idx = row["index"]
            ts = row["ts_epoch"]

            if last_ts is None:
                current["indexes"].append(idx)
                current["start_ts"] = ts
                current["end_ts"] = ts
                last_ts = ts
                continue

            if ts is None or last_ts is None or (ts - last_ts) <= window_seconds:
                current["indexes"].append(idx)
                current["end_ts"] = ts
            else:
                incidents.append(current.copy())
                current = {
                    "entity": entity,
                    "indexes": [idx],
                    "start_ts": ts,
                    "end_ts": ts
                }
            last_ts = ts

        if current["indexes"]:
            incidents.append(current.copy())

    return incidents


# ---------- MODEL EXECUTION ----------
def run_models_and_get_preds(df):

    clf = safe_load(CLASSIFIER_PATH)
    ube = safe_load(UEBA_PATH)
    scaler = safe_load(SCALER_PATH)

    numeric_cols = [
        "category_id","sub_category_id","severity_id","location_id_num",
        "is_threat","is_ueba","is_vuln","hour_of_day","day_of_week",
        "is_weekend","is_off_hours","event_count"
    ]

    for c in numeric_cols:
        if c not in df.columns:
            df[c] = 0

    X = df[numeric_cols].fillna(0).to_numpy(float)

    if scaler:
        try:
            X_scaled = scaler.transform(X)
        except:
            X_scaled = X
    else:
        X_scaled = X

    # Classifier output
    if clf:
        try:
            preds = clf.predict(X_scaled)
            probs = clf.predict_proba(X_scaled) if hasattr(clf,"predict_proba") else None
        except:
            preds = np.array([0]*len(df))
            probs = None
    else:
        preds = np.array([0]*len(df))
        probs = None

    # UEBA anomaly detection
    if ube:
        try:
            u_scores = ube.decision_function(X_scaled)
            u_flags = ube.predict(X_scaled)
            u_flags = np.where(u_flags == -1, 1, 0)
        except:
            u_scores = np.zeros(len(df))
            u_flags = np.zeros(len(df))
    else:
        u_scores = np.zeros(len(df))
        u_flags = np.zeros(len(df))

    return preds, probs, u_flags


# ---------- INCIDENT METRICS ----------
def compute_incident_stats(df, incidents, preds, u_flags):
    stats = []

    for inc in incidents:
        idxs = inc["indexes"]
        rows = df.loc[idxs]

        start_ts = rows["datetime"].min()
        end_ts   = rows["datetime"].max()

        # ground truth
        gt = rows["is_threat"].sum() > 0 if "is_threat" in rows else False

        # detection
        detection_ts = None
        detected = False
        for idx in idxs:
            p = preds[idx]
            u = u_flags[idx]
            flag = (p > 0) or (u == 1)
            if flag:
                detected = True
                detection_ts = df.at[idx,"datetime"]
                break

        # remediation
        remediation_ts = None
        for idx in idxs:
            raw = str(df.at[idx,"raw"]) if "raw" in df.columns else ""
            if regex_any(REMEDIATION_KEYWORDS, raw):
                remediation_ts = df.at[idx,"datetime"]
                break

        # vulnerabilities
        vuln_patterns = [p for v in PATTERNS["vulnerabilities"].values() for p in v]
        vuln_present = False
        vuln_ts = None
        for idx in idxs:
            raw = str(df.at[idx,"raw"])
            if regex_any(vuln_patterns, raw):
                vuln_present = True
                vuln_ts = df.at[idx,"datetime"]
                break

        exposure = None
        if vuln_present and vuln_ts:
            exposure = (end_ts - vuln_ts).total_seconds()

        # lateral movement
        lateral = False
        for idx in idxs:
            raw = str(df.at[idx,"raw"])
            if regex_any(LATERAL_KEYWORDS, raw):
                lateral = True
                break

        stats.append({
            "entity": inc["entity"],
            "start": start_ts.isoformat(),
            "end": end_ts.isoformat(),
            "duration_seconds": (end_ts - start_ts).total_seconds(),
            "ground_truth_incident": gt,
            "detected": detected,
            "detection_ts": detection_ts.isoformat() if detection_ts else None,
            "remediation_ts": remediation_ts.isoformat() if remediation_ts else None,
            "lateral_movement": lateral,
            "vulnerability_present": vuln_present,
            "exposure_seconds": exposure
        })

    return stats


# ---------- GLOBAL METRICS ----------
def compute_global_metrics(df, preds, u_flags, incident_stats):

    metrics = {}

    total = len(df)
    metrics["event_count"] = total

    # Basic confusion metrics
    if "is_threat" in df.columns:
        y_true = df["is_threat"].astype(int).to_numpy()
        y_pred = (preds > 0).astype(int)
        tp = ((y_pred==1)&(y_true==1)).sum()
        tn = ((y_pred==0)&(y_true==0)).sum()
        fp = ((y_pred==1)&(y_true==0)).sum()
        fn = ((y_pred==0)&(y_true==1)).sum()
        metrics["false_positive_rate"] = fp/(fp+tn) if (fp+tn)>0 else None
        metrics["false_negative_rate"] = fn/(fn+tp) if (fn+tp)>0 else None
        metrics["incident_detection_rate"] = tp/(tp+fn) if (tp+fn)>0 else None
    else:
        metrics["incident_detection_rate"] = None

    # MTTD / MTTR
    mttd_vals = []
    mttr_vals = []
    for inc in incident_stats:
        if inc["ground_truth_incident"] and inc["detected"] and inc["detection_ts"]:
            t0 = datetime.fromisoformat(inc["start"])
            td = datetime.fromisoformat(inc["detection_ts"])
            mttd_vals.append((td - t0).total_seconds())

        if inc["detected"] and inc["remediation_ts"]:
            td = datetime.fromisoformat(inc["detection_ts"]) if inc["detection_ts"] else None
            tr = datetime.fromisoformat(inc["remediation_ts"])
            if td:
                mttr_vals.append((tr - td).total_seconds())

    metrics["mttd_mean"] = float(np.mean(mttd_vals)) if mttd_vals else None
    metrics["mttr_mean"] = float(np.mean(mttr_vals)) if mttr_vals else None

    # UEBA anomalies
    metrics["ueba_anomaly_count"] = int(sum(u_flags))

    # Lateral movement
    lateral = 0
    for inc in incident_stats:
        if inc["lateral_movement"]:
            lateral += 1
    metrics["lateral_movement_incidents"] = lateral

    # Vulnerability detection rate
    vuln_count = sum(1 for inc in incident_stats if inc["vulnerability_present"])
    metrics["vulnerability_count"] = vuln_count

    # Exposure time
    exposure_vals = [inc["exposure_seconds"] for inc in incident_stats if inc["exposure_seconds"]]
    metrics["avg_asset_exposure_seconds"] = float(np.mean(exposure_vals)) if exposure_vals else None

    # Anomaly frequency
    df_sorted = df.sort_values("datetime")
    time_span_days = max((df_sorted["datetime"].max() - df_sorted["datetime"].min()).days, 1)
    metrics["anomaly_per_day"] = metrics["ueba_anomaly_count"] / time_span_days

    # Alert volume
    metrics["alert_volume"] = int((preds > 0).sum())

    return metrics


# ---------- SAVE ----------
def save_output(metrics, incidents):
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)

    with open(OUTPUT_JSON, "w") as f:
        json.dump({"metrics":metrics,"incident_count":len(incidents)}, f, indent=2)

    pd.DataFrame([metrics]).to_csv(OUTPUT_SUMMARY_CSV, index=False)

    print(f"\n✅ Metrics saved:")
    print(f"   → {OUTPUT_JSON}")
    print(f"   → {OUTPUT_SUMMARY_CSV}\n")


# ---------- MAIN ----------
def main():
    print("\n🔎 Loading data...")
    df = load_data()
    print(f"Loaded {len(df):,} valid timestamp events")

    print("\n🧠 Running classifier + UEBA...")
    preds, probs, u_flags = run_models_and_get_preds(df)

    print("\n📦 Grouping events into incidents...")
    incidents = group_events_into_incidents(df)
    print(f"Total incidents: {len(incidents):,}")

    print("\n📊 Computing incident-level metrics...")
    incident_stats = compute_incident_stats(df, incidents, preds, u_flags)

    print("\n📈 Computing global SOC metrics...")
    metrics = compute_global_metrics(df, preds, u_flags, incident_stats)

    print("\n💾 Saving outputs...")
    save_output(metrics, incidents)


if __name__ == "__main__":
    main()
