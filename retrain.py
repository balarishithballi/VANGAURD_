#!/usr/bin/env python3
"""
end_to_end_retrain_and_metrics_catboost.py

Replaces XGBoost/LightGBM with CatBoost (no libomp, no brew).
Fully macOS-safe.

1. Re-label threats using threat_patterns.json
2. Train CatBoost classifier (balanced)
3. Train IsolationForest for UEBA
4. Save model artifacts
5. Run inference + compute SOC metrics (MTTD, MTTR, FPR, FNR...)
"""

import os
import json
import re
import joblib
import numpy as np
import pandas as pd
from tqdm import tqdm
from datetime import datetime
from collections import Counter
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample
from sklearn.ensemble import IsolationForest
from catboost import CatBoostClassifier
import warnings
warnings.filterwarnings("ignore")

# ---------------- PATHS ----------------
FEATURES_CSV = "output/features_timeaware.csv"
THREAT_PATTERNS = "threat_patterns.json"
OUTPUT_DIR = "output"

CLASSIFIER_PATH = os.path.join(OUTPUT_DIR, "catboost_classifier.cbm")
UEBA_PATH = os.path.join(OUTPUT_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(OUTPUT_DIR, "scaler.pkl")
AUG_CSV = os.path.join(OUTPUT_DIR, "features_timeaware_augmented_catboost.csv")
METRICS_JSON = os.path.join(OUTPUT_DIR, "metrics_report_retrain.json")
METRICS_CSV = os.path.join(OUTPUT_DIR, "metrics_summary_retrain.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------- Load patterns ----------------
if os.path.exists(THREAT_PATTERNS):
    with open(THREAT_PATTERNS, "r") as f:
        PAT = json.load(f)
else:
    PAT = {"known_threats": {}, "vulnerabilities": {}, "ueba_signals": {}}

def flatten_dict(d):
    return [p for plist in d.values() for p in plist]

KNOWN = flatten_dict(PAT.get("known_threats", {}))
VULN = flatten_dict(PAT.get("vulnerabilities", {}))
UEBA = flatten_dict(PAT.get("ueba_signals", {}))

def regex_any(patterns, text):
    if text is None:
        return False
    s = str(text)
    for p in patterns:
        try:
            if re.search(p, s, re.IGNORECASE):
                return True
        except re.error:
            pass
    return False

# ---------------- Load dataset ----------------
print("🔎 Loading dataset...")
df = pd.read_csv(FEATURES_CSV, low_memory=False)

if "datetime" not in df.columns or df["datetime"].isnull().all():
    df["datetime"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", utc=True)
df = df[df["datetime"].notna()].reset_index(drop=True)
print("Loaded:", len(df))

# ---------------- Label inference ----------------
print("🏷️ Inferring threat labels...")

df["pat_threat"] = df["raw"].apply(lambda r: regex_any(KNOWN, r))
df["pat_vuln"]   = df["raw"].apply(lambda r: regex_any(VULN, r))
df["pat_ueba"]   = df["raw"].apply(lambda r: regex_any(UEBA, r))

df["is_threat"] = df["is_threat"].fillna(0).astype(int)
df["is_vuln"]   = df["is_vuln"].fillna(0).astype(int)
df["is_ueba"]   = df["is_ueba"].fillna(0).astype(int)

df.loc[df["pat_threat"], "is_threat"] = 1
df.loc[df["pat_vuln"],   "is_vuln"]   = 1
df.loc[df["pat_ueba"],   "is_ueba"]   = 1

df["label"] = ((df["is_threat"]==1) | (df["is_vuln"]==1)).astype(int)

print("Label distribution:", df["label"].value_counts().to_dict())

# ---------------- Feature matrix ----------------
NUMERIC = [
 "category_id","sub_category_id","severity_id","location_id_num",
 "is_threat","is_ueba","is_vuln",
 "hour_of_day","day_of_week","is_weekend","is_off_hours","event_count"
]

for c in NUMERIC:
    if c not in df.columns:
        df[c] = 0

X = df[NUMERIC].fillna(0).astype(float).to_numpy()
y = df["label"].astype(int).to_numpy()

# ---------------- Scaler ----------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, SCALER_PATH)

# ---------------- Balance ----------------
pos = df[df["label"]==1]
neg = df[df["label"]==0]

if len(pos) < len(neg):
    pos_up = resample(pos, replace=True, n_samples=len(neg), random_state=42)
    df_bal = pd.concat([neg, pos_up])
else:
    df_bal = df

X_bal = df_bal[NUMERIC].fillna(0).astype(float).to_numpy()
y_bal = df_bal["label"].astype(int).to_numpy()
X_bal_scaled = scaler.transform(X_bal)

print("Balanced:", Counter(y_bal))

# ---------------- Train CatBoost ----------------
print("🚀 Training CatBoost (no OpenMP needed)...")

clf = CatBoostClassifier(
    iterations=400,
    depth=8,
    learning_rate=0.05,
    loss_function="Logloss",
    verbose=False,
    random_seed=42
)

clf.fit(X_bal_scaled, y_bal)
clf.save_model(CLASSIFIER_PATH)
print("✅ Saved classifier:", CLASSIFIER_PATH)

# ---------------- Train UEBA ----------------
print("🌐 Training UEBA IsolationForest...")

normal_df = df[df["label"]==0]
sample = min(40000, len(normal_df))
normal_sample = normal_df.sample(sample, random_state=42)

X_ueba = normal_sample[NUMERIC].fillna(0).astype(float).to_numpy()
X_ueba_scaled = scaler.transform(X_ueba)

iso = IsolationForest(n_estimators=150, contamination=0.01, random_state=42)
iso.fit(X_ueba_scaled)

joblib.dump(iso, UEBA_PATH)
print("✅ Saved UEBA model:", UEBA_PATH)

# ---------------- Inference ----------------
print("🔁 Running inference...")

X_full = scaler.transform(df[NUMERIC].fillna(0).astype(float).to_numpy())
preds = clf.predict(X_full).astype(int)
probs = clf.predict_proba(X_full)[:,1]

u_scores = iso.decision_function(X_full)
u_labels = iso.predict(X_full)
u_flags = np.where(u_labels == -1, 1, 0)

df["predicted_label"] = preds
df["predicted_prob"] = probs
df["ueba_flag"] = u_flags
df["ueba_score"] = u_scores

df.to_csv(AUG_CSV, index=False)
print("📁 Saved augmented:", AUG_CSV)

# ---------------- Metrics ----------------
print("📊 Computing SOC metrics...")

y_true = df["label"].to_numpy()
y_pred = preds

tp = int(((y_pred==1)&(y_true==1)).sum())
tn = int(((y_pred==0)&(y_true==0)).sum())
fp = int(((y_pred==1)&(y_true==0)).sum())
fn = int(((y_pred==0)&(y_true==1)).sum())

fpr = fp/(fp+tn) if (fp+tn)>0 else None
fnr = fn/(fn+tp) if (fn+tp)>0 else None

alert_volume = int((y_pred==1).sum())

ueba_count = int(u_flags.sum())
days = max(1, (df["datetime"].max() - df["datetime"].min()).days)
anomaly_per_day = ueba_count / days

metrics = {
    "event_count": len(df),
    "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    "false_positive_rate": fpr,
    "false_negative_rate": fnr,
    "alert_volume": alert_volume,
    "ueba_anomaly_count": ueba_count,
    "anomaly_per_day": anomaly_per_day,
}

with open(METRICS_JSON, "w") as fh:
    json.dump(metrics, fh, indent=2)

pd.DataFrame([metrics]).to_csv(METRICS_CSV, index=False)

print("\n🎉 ALL DONE — CatBoost pipeline completed successfully.")
print("Metrics:", metrics)
