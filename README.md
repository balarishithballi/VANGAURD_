📌 Overview

This project is a complete security analytics pipeline that performs:

Log parsing and normalization

Data cleaning and validation

Feature engineering for SIEM + UEBA

Threat detection using supervised and unsupervised ML

Anomaly scoring, risk scoring, and incident grouping

Dashboard generation

SHAP-based model explainability

The system supports signature-based detection, behavior-based UEBA, and ML-driven threat scoring.

🏗️ Architecture
Raw Logs → Log Parser → Clean Data → Feature Engineering → 
Model Training → Inference → Risk Score → Incident Grouping → Dashboard


Each stage is implemented in modular Python files:

Module	Purpose
log_parser_1.py	Detect log types, extract fields, normalize timestamps
clean_data_2.py	Remove duplicates, normalize columns, validate IPs/URLs
feature_engineering_3.py	Generate numerical, categorical, regex, text, UEBA features
retrain4.py	Model training, retraining, hyperparameter tuning
risK_score5.py	Combine ML output into unified risk score
shap6.py	SHAP explainability for SOC analysts
dashboard7.py	Visualization and SOC reporting
generator.py	Synthetic log generator for testing
main.py	Orchestration pipeline

Threat and behavior patterns are loaded from:

threat_patterns.json 

threat_patterns

📂 1. Log Parsing (log_parser_1.py)
Purpose

Convert raw heterogeneous logs into structured JSON with unified fields.

Key Steps

Reads logs line-by-line

Detects log type using regex

Extracts fields (IP, URL, status code, timestamps, PID, ports, etc.)

Adds metadata:

source

raw

event_type

Normalizes timestamps to ISO-8601 UTC

Merges all logs into a unified JSON structure

🧹 2. Data Cleaning (clean_data_2.py)
Removes or fixes:

Empty or corrupted logs

Duplicate entries

Invalid IPs, URLs, timestamps

Noise logs (unnecessary system noise)

Reserved IP ranges

Missing fields (imputation)

Normalization Includes

Timestamp standardization

Column naming consistency

Extracting hidden fields from log messages

🔧 3. Feature Engineering (feature_engineering_3.py)

Features are converted into ML-ready numeric/categorical vectors.

3.1 Basic Features

Examples:

src/dst IP

src/dst port

response size

event type

host

method

device type

PID

OPS

3.2 Text-Based Features

log length

number of digits

special characters

suspicious keywords (SQL, shell commands)

regex-based signature matches

3.3 Threat Pattern Features

Matches patterns from threat_patterns.json 

threat_patterns

:

brute-force

SQL injection

XSS

RCE

malware activity

ransomware

port scanning

DoS attacks

privilege escalation

credential dumping

lateral movement

data exfiltration

Binary output: 1 = matched, 0 = no match

3.4 UEBA Behavioral Features

Examples:

odd-hour login

login from new country

failed attempts in 10 min

time since last login

event rate per user

new device / new user-agent

abnormal query volumes

large outbound transfers

3.5 Time-Series Features

hour of day

weekday

weekend indicator

off-hours flag

time since previous event

rolling window behavior (EWMA)

3.6 Encoding

One-hot encoding (event types)

Label encoding (categorical → integer)

Hash encoding (usernames, IPs, process names)

🤖 4. Machine Learning (retrain4.py)

The pipeline supports both supervised and unsupervised models.

Supervised Models

Used when training labels exist (TP/FP/FN/TN):

CatBoost (primary classifier)

XGBoost

Logistic Regression (baseline)

These models predict threat probability for each event.

Unsupervised Models

Used for UEBA anomaly scoring:

Isolation Forest

Other anomaly detection modules (depending on config)

Output: anomaly score (0–1)

Training Pipeline

Load datasets

Handle imbalance

Train–Test split

Hyperparameter tuning

Save model artifacts

Export evaluation metrics

🔥 5. Risk Scoring (risK_score5.py)

Final risk score combines:

Risk = f(threat_probability, anomaly_score, signature_matches, UEBA_signals)


This gives a unified score used by SOC analysts.

📊 6. Incidents & Dashboard (dashboard7.py)

Group alerts into incidents using a 1-hour window

Summaries include:

Total alerts

UEBA anomalies

Incident count

Trends

Geolocation statistics

Top risky users/IPs

Visualization produced in HTML/PNG/interactive dashboards.

📈 7. Explainability (shap6.py)

Uses SHAP to explain model predictions:

Which feature caused the alert

Contribution of UEBA vs signature vs ML

Helps SOC perform RCA (root-cause analysis)

🧪 8. Synthetic Log Generation (generator.py)

Generates random logs for:

Testing

Demo

Validating pipeline stability

🚀 9. Results (Sample ML Metrics)

From your latest results:

event_count: 154332
true_positives: 20224
true_negatives: 134102
false_positives: 6
false_negatives: 0
false_positive_rate: 4.47e-05
false_negative_rate: 0.0
alert_volume: 20230
ueba_anomaly_count: 2636
anomaly_per_day: ~7.24
incident_count: 8289

Interpretation:

Extremely low false positives

Zero false negatives

Consistent UEBA anomaly detection

High-quality threat classification

🛠️ 10. Requirements
Python Version
Python 3.8+

Install Dependencies
pip install -r requirements.txt

Typical required libraries:
pandas
numpy
regex
scikit-learn
xgboost
catboost
shap
matplotlib
seaborn
ipaddress
python-dateutil
pyyaml
tqdm
fastapi (if API is enabled)
uvicorn

▶️ 11. Running the Pipeline
Full pipeline
python main.py

Retrain models
python retrain4.py

Generate dashboard
python dashboard7.py

Explainability
python shap6.py

🧱 12. Project Structure
project/
│
├── log_parser_1.py
├── clean_data_2.py
├── feature_engineering_3.py
├── retrain4.py
├── risk_score5.py
├── shap6.py
├── dashboard7.py
├── generator.py
├── main.py
├── threat_patterns.json
├── README.md
└── requirements.txt

🎯 13. Key Strengths of This System

Hybrid Signature + ML + UEBA approach

Very low false positives

Zero-day behavior detection via UEBA

Explainable via SHAP

Modular and scalable

Works for SOC automation
