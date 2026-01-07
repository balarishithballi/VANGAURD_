#!/usr/bin/env python3
import os
import json
import re
import numpy as np
import pandas as pd
from tqdm import tqdm
from datetime import datetime
from collections import defaultdict

from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.preprocessing import StandardScaler
import scipy.sparse as sp
import joblib

# ---------------- CONFIG ----------------
INPUT_FILE = "cleaned_logs.csv"       # << UPDATED
PATTERN_FILE = "threat_patterns.json"
OUTPUT_DIR = "output"

OUTPUT_JSON = os.path.join(OUTPUT_DIR, "features_timeaware.jsonl")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "features_timeaware.csv")

HYBRID_X = os.path.join(OUTPUT_DIR, "hybrid_features_sparse.npz")
HYBRID_Y = os.path.join(OUTPUT_DIR, "hybrid_labels.npy")
SCALER_PATH = os.path.join(OUTPUT_DIR, "hybrid_scaler.pkl")
MODEL_NOTE = os.path.join(OUTPUT_DIR, "embedding_model_name.txt")

VECTORIZER_NAME = "HashingVectorizer_sparse_2^15_ngram(1,3)"

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("""
==========================================================
 GT-SAFE FEATURE PIPELINE
----------------------------------------------------------
✔ ground_truth (gt) is imported from CSV
✔ gt is written to final CSV
✔ gt becomes the ONLY ML target label (y)
✘ gt does NOT affect:
   - threat detection
   - severity
   - sub_category
   - category
   - UEBA features
   - numeric or text embeddings
==========================================================
""")


# ---------------- LOAD THREAT PATTERNS ----------------
def load_patterns():
    if not os.path.exists(PATTERN_FILE):
        return {"known_threats":{}, "vulnerabilities":{}, "ueba_signals":{}}
    try:
        return json.load(open(PATTERN_FILE))
    except:
        return {"known_threats":{}, "vulnerabilities":{}, "ueba_signals":{}}

PAT = load_patterns()


# ---------------- SAFE REGEX MATCH ----------------
def safe_match(patterns, text):
    if not text:
        return False
    for p in patterns:
        try:
            if re.search(p, text, re.IGNORECASE):
                return True
        except:
            pass
    return False


# ---------------- THREAT DETECTION (NO GT INFLUENCE) ----------------
def detect_threat(entry):
    raw = (entry.get("raw") or "").lower()

    # Pattern matching (known threats)
    for name, lst in PAT["known_threats"].items():
        if safe_match(lst, raw):
            return "known_threat", name

    # Vulnerabilities
    for name, lst in PAT["vulnerabilities"].items():
        if safe_match(lst, raw):
            return "vulnerability", name

    # UEBA anomalies
    for name, lst in PAT["ueba_signals"].items():
        if safe_match(lst, raw):
            return "ueba_anomaly", name

    # Severity fallback
    if entry.get("severity") == "high":
        return "unknown_threat", "unclassified_high_risk"

    return "benign", None


# ---------------- CATEGORICAL ENCODERS ----------------
ENCODERS = defaultdict(dict)
COUNT = defaultdict(int)

def encode(field, value):
    if value not in ENCODERS[field]:
        ENCODERS[field][value] = COUNT[field]
        COUNT[field] += 1
    return ENCODERS[field][value]


# ---------------- UEBA TIME FEATURES ----------------
def ueba_time(df):
    df["datetime"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["datetime"]).copy()

    df["hour_of_day"] = df["datetime"].dt.hour
    df["day_of_week"] = df["datetime"].dt.dayofweek
    df["is_weekend"] = df["day_of_week"] >= 5
    df["is_off_hours"] = df["hour_of_day"].isin(range(0, 5))

    # Per-user event density
    if "user" in df.columns:
        df["hour_bucket"] = df["datetime"].dt.floor("h")
        density = df.groupby(["user","hour_bucket"])["timestamp"].count().reset_index()
        density.columns = ["user","hour_bucket","event_count"]
        df = df.merge(density, on=["user","hour_bucket"], how="left")
        th = density["event_count"].mean() or 1
        df["ueba_burst"] = df["event_count"] > (th * 5)
    else:
        df["event_count"] = 1
        df["ueba_burst"] = False

    df["ueba_time_anomaly"] = df["is_off_hours"] | df["is_weekend"] | df["ueba_burst"]
    return df


# ---------------- MAIN FEATURE ENGINEERING ----------------
def feature_engineer():
    print("🚀 Starting feature engineering…")

    # ---- LOAD CSV ----
    df_input = pd.read_csv(INPUT_FILE)
    print(f"Loaded rows: {len(df_input):,}")

    rows = []

    for _, e_raw in tqdm(df_input.iterrows(), total=len(df_input)):
        e = e_raw.to_dict()

        # Ground Truth (ONLY for y)
        e["gt"] = int(e.get("gt", e.get("ground_truth", 0)))

        # Threat detection (NO GT usage)
        ttype, subtype = detect_threat(e)
        e["threat_type"] = ttype
        e["threat_subtype"] = subtype or "none"

        # Categorical encodings
        e["category_id"] = encode("category", e.get("category","unknown"))
        e["sub_category_id"] = encode("sub_category", e.get("sub_category","general"))
        e["severity_id"] = encode("severity", e.get("severity","low"))
        e["location_id_num"] = encode("location_id", e.get("location_id","UNK"))
        e["threat_type_id"] = encode("threat_type", ttype)

        # Boolean flags (ML features)
        e["is_threat"] = int("threat" in ttype)
        e["is_ueba"] = int("ueba" in ttype)
        e["is_vuln"] = int("vulnerability" in ttype)

        rows.append(e)

    df = pd.DataFrame(rows)
    print(f"📦 Feature-engineered logs: {len(df):,}")

    # ---- UEBA TIME-BASED FEATURES ----
    df = ueba_time(df)

    # Upgrade UEBA flag
    df.loc[df["ueba_time_anomaly"], "is_ueba"] = 1

    # ---- SAVE OUTPUT FILES ----
    df.to_csv(OUTPUT_CSV, index=False)
    df.to_json(OUTPUT_JSON, orient="records", lines=True)

    print("✅ Feature engineering complete.")
    return df


# ---------------- REAL-TIME SPARSE TEXT EMBEDDINGS ----------------
def vectorize_sparse(df):
    print("\n⚡ HashingVectorizer → SPARSE embeddings")

    texts = df["raw"].fillna("").astype(str).tolist()

    vectorizer = HashingVectorizer(
        n_features=2**15,
        alternate_sign=False,
        ngram_range=(1,3),
        norm="l2",
        lowercase=True
    )

    print("🔁 Transforming text…")
    X_text = vectorizer.transform(texts)

    NUMERIC = [
        "category_id","sub_category_id","severity_id","location_id_num",
        "is_threat","is_ueba","is_vuln",
        "hour_of_day","day_of_week","is_weekend","is_off_hours","event_count",
    ]

    for c in NUMERIC:
        if c not in df:
            df[c] = 0

    X_num = df[NUMERIC].astype(float).to_numpy()
    scaler = StandardScaler()
    X_num_scaled = scaler.fit_transform(X_num)
    joblib.dump(scaler, SCALER_PATH)

    X_num_sparse = sp.csr_matrix(X_num_scaled)

    print("🔗 Combining numeric + text vectors…")
    X_hybrid = sp.hstack([X_num_sparse, X_text]).tocsr()

    # LABEL = ONLY ground_truth
    y = df["gt"].to_numpy(int)

    sp.save_npz(HYBRID_X, X_hybrid)
    np.save(HYBRID_Y, y)

    with open(MODEL_NOTE, "w") as f:
        f.write(VECTORIZER_NAME)

    print("✅ Saved hybrid sparse feature matrix (X) + labels (y)")


# ---------------- MAIN ----------------
if __name__ == "__main__":
    df = feature_engineer()
    vectorize_sparse(df)
    print("\n🎉 COMPLETE: GT-SAFE FEATURE PIPELINE READY FOR ML")
