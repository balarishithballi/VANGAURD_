# 🛡️ VANGUARD  
### AI-Powered Threat Detection, UEBA & Security Analytics Pipeline  
**Logs → Parse → Clean → Features → ML → Risk Scoring → SHAP Explainability → Dashboard**

Vanguard is an **AI-driven SIEM / Security Analytics pipeline** designed to process heterogeneous logs, extract features, detect anomalies, assign risk scores, and provide SHAP-based explainability — all visualized in a SOC dashboard.

This README matches **exactly your project structure and current files**.

---

# 📁 PROJECT STRUCTURE

```
VANGUARD/
├── logs/
├── output/
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
├── catboost_info/
├── log_parser.py
├── clean_data.py
├── compute.py
├── retrain.py
├── risk_score.py
├── explain_event_shap.py
├── dashboard.py
├── feature_engineering.py
├── vector.py
├── generator.py
└── threat_patterns.json
```

---

# 🚀 FULL PIPELINE EXECUTION

## STEP 1 — Parse Logs
```bash
python3 log_parser.py
```

## STEP 2 — Clean Data
```bash
python3 clean_data.py
```

## STEP 3 — Compute SOC Metrics
```bash
python3 compute.py
```

## STEP 4 — Retrain ML Models
```bash
python3 retrain.py
```

## STEP 5 — Risk Scoring
```bash
python3 risk_score.py
```

## STEP 6 — SHAP Explainability
```bash
python3 explain_event_shap.py --sample 500
```

## STEP 7 — Streamlit Dashboard
```bash
streamlit run dashboard.py
```

---

# 🔥 ONE-SHOT PIPELINE
```bash
python3 log_parser.py
python3 clean_data.py
python3 compute.py
python3 retrain.py
python3 risk_score.py
python3 explain_event_shap.py --sample 1000000
streamlit run dashboard.py
```

---

# 📌 REQUIREMENTS
```
pip install -r requirements.txt
```

---

# 📜 LICENSE
MIT License
