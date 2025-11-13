🛡️ VANGUARD
AI-Powered Threat Detection, UEBA & Security Analytics Pipeline

Logs → Parse → Clean → Features → ML → Risk Scoring → SHAP Explainability → Dashboard

Vanguard is an AI-driven SIEM / Security Analytics pipeline designed to process heterogeneous logs, extract features, detect anomalies, assign risk scores, and provide SHAP-based explainability — all visualized in a SOC dashboard.

This README matches exactly your project structure and current files.

📁 PROJECT STRUCTURE
VANGUARD/
│
├── logs/                              # Raw log input folder  
│
├── output/                            # Processed datasets, models, metrics  
│   ├── cleaned_logs.jsonl  
│   ├── merged_logs.jsonl  
│   ├── features_timeaware.csv  
│   ├── features_timeaware_augmented_catboost.csv  
│   ├── features_timeaware_augmented_catboost_with_risk.csv  
│   ├── catboost_classifier.cbm  
│   ├── isolation_forest.joblib  
│   ├── scaler.pkl  
│   ├── metrics_report.json  
│   ├── metrics_summary.csv  
│   └── shap_cache.parquet  
│
├── catboost_info/                     # Auto-generated CatBoost logs  
│
├── log_parser.py                      # STEP 1 — Parse logs  
├── clean_data.py                      # STEP 2 — Clean & normalize  
├── compute.py                         # STEP 3 — SOC metrics  
├── retrain.py                         # STEP 4 — ML training  
├── risk_score.py                      # STEP 5 — Risk scoring  
├── explain_event_shap.py              # STEP 6 — SHAP explainability  
├── dashboard.py                       # STEP 7 — Streamlit dashboard  
│
├── feature_engineering.py             # Legacy feature builder  
├── vector.py                          # Legacy vectorizer  
├── generator.py                       # Optional log generator  
│
└── threat_patterns.json               # Threat, UEBA & vuln patterns  

🚀 FULL PIPELINE EXECUTION (Your Exact Steps)
1️⃣ STEP 1 — Log Parsing

Parses any .log file inside ./logs/:

system logs

auth/secure logs

audit logs

Apache/Web logs

firewall / IDS logs

cloud logs

DB transaction logs

USB activity

custom application logs

python3 log_parser.py


Outputs:

output/merged_logs.jsonl

2️⃣ STEP 2 — Clean & Normalize Data

Handles:

timestamp fixing

missing fields

category/severity mapping

flatten nested logs

first-level UEBA pattern extraction

ML-ready table creation

python3 clean_data.py


Outputs:

output/cleaned_logs.jsonl

output/features_timeaware.csv

3️⃣ STEP 3 — Compute SOC Metrics

Generates operational threat analytics:

TP / FP / FN / TN

FPR / FNR

Incident detection rate

MTTD / MTTR

UEBA anomaly counts

Lateral movement detection

Daily/hourly event distribution

python3 compute.py


Outputs:

output/metrics_report.json

output/metrics_summary.csv

4️⃣ STEP 4 — Model Retraining

Trains:

CatBoost Classifier

Chosen because macOS does not support XGBoost OpenMP

Strong for tabular security data

Handles categorical / missing values natively

IsolationForest (UEBA)

Detects insider threats

Lateral movement

Unknown anomalies

Rare event patterns

python3 retrain.py


Outputs:

output/catboost_classifier.cbm

output/isolation_forest.joblib

output/scaler.pkl

output/features_timeaware_augmented_catboost.csv

5️⃣ STEP 5 — Hybrid Risk Score (0–100)

Risk scoring formula used by your pipeline:

risk_score =
  0.50 * ML probability
+ 0.30 * UEBA anomaly magnitude
+ 0.15 * Threat Intel / pattern match
+ 0.05 * vuln + lateral movement signals


Output is scaled to 0–100.

python3 risk_score.py


Output:

output/features_timeaware_augmented_catboost_with_risk.csv

6️⃣ STEP 6 — SHAP Explainability

Explain why a specific prediction was made.

Explain a single event:
python3 explain_event_shap.py --event-index 100

Precompute SHAP for 500 samples:
python3 explain_event_shap.py --sample 500 --out output/shap_cache.parquet


This allows the dashboard to load explanations instantly.

7️⃣ STEP 7 — SOC Dashboard (Streamlit)

Start UI:

streamlit run dashboard.py


Open:

http://localhost:8501

Dashboard Includes:

Alerts timeline

UEBA anomaly heatmap

High-risk event explorer

Risk score distribution

Top IPs / Subnets / Users

Daily event volume

ML prediction confidence

SHAP explainability viewer

Full log search & filtering

🧠 TECHNICAL DETAILS
Log Parsing (log_parser.py)

Supports:

system.log

auth.log, secure.log

audit.log

access.log, apache.log

firewall.log, ids.log

cloud audit logs

app/service logs

JSON logs

unstructured plain-text logs

Automatically handles:

timestamp extraction

hostname parsing

event category inference

threat-keyword detection

normalizing heterogeneous formats

Feature Engineering (clean_data.py)

Features extracted:

hour_of_day

day_of_week

is_off_hours

severity levels

category IDs

entity-based UEBA

failed/success pattern tracking

count-based anomaly features

sliding window activity

multi-source merging

Machine Learning (retrain.py)
CatBoost

Used due to:

macOS compatibility

low memory usage

high accuracy

native categorical handling

IsolationForest

Used for UEBA detection of:

rare behavior

privilege escalation

lateral movement sequences

anomalous login timing

infrequent resource access

Risk Engine (risk_score.py)

Inputs combined:

ML Probability

UEBA Anomaly Score

Threat Patterns (from threat_patterns.json)

Vuln/Lateral Movement Signals

Produces standardized risk from 0 → 100.

SOC Metrics (compute.py)

Calculates:

detection accuracy

precision/recall

FPR / FNR

MTTD (Mean Time to Detect)

MTTR (Mean Time to Respond)

hourly event heatmaps

UEBA cluster statistics

incident aggregation

🔥 FULL PIPELINE (One Shot Command Set)
python3 log_parser.py
python3 clean_data.py
python3 compute.py
python3 retrain.py
python3 risk_score.py
python3 explain_event_shap.py --sample 1000000
streamlit run dashboard.py
