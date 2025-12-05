# 🛡️ Security Analytics Pipeline & SIEM/UEBA System

## 📌 Overview
This project is a complete security analytics pipeline designed for modern SOC environments. It integrates log parsing, data cleaning, advanced feature engineering, and hybrid threat detection using both supervised machine learning and unsupervised UEBA (User and Entity Behavior Analytics).

**Key Capabilities:**
*   **Hybrid Detection:** Supports signature-based detection, behavior-based UEBA, and ML-driven threat scoring.
*   **End-to-End Processing:** From raw log ingestion to incident grouping and dashboard generation.
*   **Explainable AI:** Includes SHAP-based model explainability to assist SOC analysts in Root Cause Analysis (RCA).

---

## 🏗️ Architecture
The data flow follows a linear, modular pipeline:

`Raw Logs` → `Log Parser` → `Clean Data` → `Feature Engineering` → `Model Training` → `Inference` → `Risk Score` → `Incident Grouping` → `Dashboard`

### Module Breakdown

| Module | File Name | Purpose |
| :--- | :--- | :--- |
| **Parsing** | `log_parser_1.py` | Detect log types, extract fields, normalize timestamps. |
| **Cleaning** | `clean_data_2.py` | Remove duplicates, normalize columns, validate IPs/URLs. |
| **Features** | `feature_engineering_3.py` | Generate numerical, categorical, regex, text, and UEBA features. |
| **ML Core** | `retrain4.py` | Model training, retraining, and hyperparameter tuning. |
| **Scoring** | `risk_score5.py` | Combine ML output into a unified risk score. |
| **XAI** | `shap6.py` | SHAP explainability for SOC analysts. |
| **Reporting** | `dashboard7.py` | Visualization, incident grouping, and SOC reporting. |
| **Generator** | `generator.py` | Synthetic log generator for testing/validation. |
| **Orchestrator** | `main.py` | Main execution entry point for the pipeline. |

> **Note:** Threat and behavior patterns are loaded from `threat_patterns.json`.

---

## 📂 1. Log Parsing (`log_parser_1.py`)
**Purpose:** Convert raw heterogeneous logs into structured JSON with unified fields.

**Key Steps:**
*   Reads logs line-by-line.
*   Detects log type using Regex.
*   **Field Extraction:** Extracts IP, URL, status code, timestamps, PID, ports, etc.
*   **Metadata Enrichment:** Adds `source`, `raw`, and `event_type`.
*   **Normalization:** Converts all timestamps to **ISO-8601 UTC**.
*   Merges all logs into a unified JSON structure.

---

## 🧹 2. Data Cleaning (`clean_data_2.py`)
Ensures data quality by removing noise and fixing errors.

**Actions:**
*   **Removals:** Empty/corrupted logs, duplicate entries, and system noise.
*   **Validation:** Filters invalid IPs, URLs, and timestamps; removes reserved IP ranges.
*   **Imputation:** Handles missing fields.
*   **Normalization:** Standardizes column names and extracts hidden fields from unstructured log messages.

---

## 🔧 3. Feature Engineering (`feature_engineering_3.py`)
Converts raw data into ML-ready numeric/categorical vectors.

### 3.1 Basic Features
*   Src/Dst IP & Port
*   Response Size
*   Event Type, Host, Method
*   Device Type, PID, OPS

### 3.2 Text-Based Features
*   Log length, digit count, special character count.
*   Suspicious keyword detection (e.g., SQL syntax, shell commands).
*   Regex-based signature matches.

### 3.3 Threat Pattern Features
Matches patterns defined in `threat_patterns.json` (Binary Output: 1 = matched, 0 = no match).
*   *Attack Types:* Brute-force, SQL injection, XSS, RCE, Malware, Ransomware, Port scanning, DoS, Privilege escalation, Credential dumping, Lateral movement, Data exfiltration.

### 3.4 UEBA Behavioral Features
*   Odd-hour logins or logins from new countries.
*   High frequency of failed attempts (e.g., within 10 mins).
*   Time since last login.
*   New device/User-Agent detection.
*   Abnormal query volumes or large outbound transfers.

### 3.5 Time-Series Features
*   Hour of day, weekday vs. weekend, off-hours flag.
*   Time since previous event.
*   Rolling window behavior (EWMA).

### 3.6 Encoding
*   **One-hot:** Event types.
*   **Label:** Categorical → Integer.
*   **Hashing:** Usernames, IPs, process names.

---

## 🤖 4. Machine Learning (`retrain4.py`)
The pipeline utilizes a hybrid approach with both Supervised and Unsupervised models.

### Supervised Models (Threat Probability)
Used when training labels (TP/FP/FN/TN) exist.
*   **CatBoost** (Primary Classifier)
*   XGBoost
*   Logistic Regression (Baseline)

### Unsupervised Models (Anomaly Detection)
Used for UEBA anomaly scoring (Output score 0–1).
*   Isolation Forest
*   Additional anomaly detection modules (configurable).

**Training Pipeline:** Load Datasets → Handle Imbalance → Train-Test Split → Hyperparameter Tuning → Save Artifacts → Export Metrics.

---

## 🔥 5. Risk Scoring (`risk_score5.py`)
Calculates a unified risk score for SOC analysts:
$$ \text{Risk} = f(\text{Threat Probability}, \text{Anomaly Score}, \text{Signature Matches}, \text{UEBA Signals}) $$

---

## 📊 6. Incidents & Dashboard (`dashboard7.py`)
*   **Incident Grouping:** Groups alerts into incidents using a **1-hour window**.
*   **Visualization:** Outputs HTML/PNG/Interactive dashboards.
*   **Summaries:** Total alerts, UEBA anomalies, incident counts, trends, geolocation stats, and top risky users/IPs.

---

## 📈 7. Explainability (`shap6.py`)
Uses **SHAP (SHapley Additive exPlanations)** to provide transparency for model predictions.
*   Identifies which specific feature caused the alert.
*   Differentiates between contributions from UEBA, signatures, or ML patterns.

---

## 🧪 8. Synthetic Log Generation (`generator.py`)
Generates random, realistic logs for:
*   System testing.
*   Demos.
*   Validating pipeline stability.

---

## 🚀 9. Performance Metrics (Sample Results)
Based on the latest test run:

| Metric | Value |
| :--- | :--- |
| **Event Count** | 154,332 |
| **True Positives** | 20,224 |
| **True Negatives** | 134,102 |
| **False Positives** | 6 |
| **False Negatives** | 0 |
| **FP Rate** | 4.47e-05 |
| **Alert Volume** | 20,230 |
| **UEBA Anomalies** | 2,636 |

**Interpretation:**
*   ✅ Extremely low false positives.
*   ✅ Zero false negatives.
*   ✅ High-quality threat classification and consistent UEBA detection.

---

## 🛠️ 10. Requirements

*   **Python Version:** 3.8+

**Dependencies:**
*Typical libraries include:* `pandas`, `numpy`, `regex`, `scikit-learn`, `xgboost`, `catboost`, `shap`, `matplotlib`, `seaborn`, `ipaddress`, `python-dateutil`, `pyyaml`, `tqdm`, `fastapi`, `uvicorn`.

---

## ▶️ 11. Usage Instructions

**Run Full Pipeline:**
# 📄 generator.py — Synthetic Log Generator

## 📘 Overview
The `generator.py` module is a **synthetic security log generator** that creates realistic, randomized logs for testing and demonstration purposes. It supports both benign and malicious log generation with configurable attack patterns and frequencies.

---

## ✅ Purpose
The synthetic log generator serves multiple critical functions:

*   **End-to-End Testing:** Validate the entire pipeline (parser → cleaning → features → ML → scoring).
*   **Stress Testing:** Evaluate system performance with large-scale datasets.
*   **Controlled Scenarios:** Generate specific attack types (SQLi, XSS, brute-force, RCE, etc.) in isolation.
*   **Safe Demonstrations:** Run demos without exposing real production security data.
*   **Model Training & Validation:** Create labeled datasets for supervised learning experiments.

---

## 🚀 How It Works

### 1. Event Type Selection
Randomly selects from predefined log types:
*   **SSH/Login Events** – Authentication attempts, successes, failures.
*   **HTTP Requests** – Web server logs (Apache, Nginx).
*   **Database Access** – SQL queries and database operations.
*   **System Events** – Process execution, privilege changes, network connections.
*   **Application Logs** – Custom application events, errors, warnings.

### 2. Field Generation
For each event, the generator creates:
*   **Source IP** – Random internal or external IPv4.
*   **Destination IP** – Server or resource address.
*   **Timestamp** – ISO-8601 formatted, with configurable time range.
*   **Username/User ID** – Random user identities or service accounts.
*   **Port Numbers** – Random or service-specific (22, 80, 443, 3306, etc.).
*   **Device Info** – Device types, hostnames, operating systems.
*   **HTTP Method** – GET, POST, PUT, DELETE (for web logs).
*   **Status Codes** – HTTP response codes or system status.
*   **Process IDs (PID)** – Random process identifiers.
*   **User-Agents** – Browser or application identifiers.

### 3. Threat Pattern Embedding
For malicious logs, the generator injects **attack signatures** into fields:

#### Attack Types Supported:

| Attack Type | Example | Injection Point |
| :--- | :--- | :--- |
| **SQL Injection** | `' OR '1'='1'; DROP TABLE users--` | URL/Query parameter |
| **XSS (Cross-Site Scripting)** | `<script>alert('XSS')</script>` | Request body/URL |
| **Brute Force** | Multiple failed login attempts | Authentication log |
| **RCE (Remote Code Execution)** | `; cat /etc/passwd` | Command injection in URL |
| **Path Traversal** | `../../etc/passwd` | URL path |
| **Command Injection** | `ls && whoami` | Shell command execution |
| **Malware Activity** | Suspicious process names, encoded payloads | Process execution logs |
| **Port Scanning** | Multiple connection attempts on different ports | Network connection logs |
| **DoS/DDoS** | High-frequency requests from single IP | HTTP request logs |
| **Credential Dumping** | Suspicious registry/memory access | System event logs |
| **Lateral Movement** | Admin share access, remote execution | Network events |
| **Data Exfiltration** | Large outbound data transfers | Network flow logs |

### 4. Raw Log Output
Generated logs closely mimic real-world formats:

Jan 11 12:43:22 server sshd: Failed password for root from 192.168.1.34 port 51432
Jan 11 12:44:05 webserver apache2: 203.0.113.45 - - [11/Jan/2025:12:44:05 +0000] "GET /admin.php?id=1' OR '1'='1 HTTP/1.1" 200 1024
Jan 11 12:45:10 db-server mysql: User 'admin' executed: SELECT * FROM users WHERE id = 5 AND password = 'pass123'
Jan 11 12:46:33 workstation kernel: [152034.123456] audit: type=EXECVE msg=audit(1641900393.456:789): argc=3 a0="/bin/bash" a1="-c" a2="rm -rf /"

text

### 5. Dataset Modes
The generator supports multiple generation modes:

*   **Pure Normal Logs:** Benign activity only (for baseline comparisons).
*   **Pure Attack Logs:** Malicious activity only (for attack pattern studies).
*   **Mixed Dataset:** Blended normal + attack logs (realistic training data).
*   **Custom Profiles:** User-defined distributions and patterns.

---

## 🧩 Key Features

### Randomization & Control
*   **Event Type Randomization:** Randomly selects log types following a configurable distribution.
*   **Temporal Variation:** Generates logs across multiple days/weeks with realistic patterns (off-hours vs. business hours).
*   **IP Address Pools:** Draws from configurable internal/external IP ranges.
*   **User Profiles:** Supports multiple users with consistent behavioral patterns.

### Attack Pattern Injection
*   **Configurable Attack Frequency:** Set the ratio of malicious to benign logs.
*   **Attack Type Selection:** Choose specific attacks to inject or randomize.
*   **Payload Variation:** Multiple variations of each attack type to avoid overfitting.
*   **Stealth Options:** Generate obfuscated or encoded payloads.

### Performance & Scaling
*   **High-Volume Generation:** Generate 100K+ logs in seconds.
*   **Memory Efficiency:** Stream logs without loading entire dataset into memory.
*   **Batch Processing:** Generate logs in configurable batches.

### Configuration
Generator behavior controlled via:
*   **CLI Arguments** – Command-line parameters.
*   **Configuration File** – YAML/JSON config for complex scenarios.
*   **Programmatic API** – Import and use in custom Python scripts.

---

## 📤 Output Formats

### 1. Raw Text File
/generated/logs_sample.txt

Plain text format, one log per line. Suitable for log parser testing.

### 2. JSON Format
/generated/logs_sample.json

Structured JSON array of log objects with metadata.

### 3. CSV Format
/generated/logs_sample.csv


Tabular format for direct ingestion into spreadsheets or databases.

### 4. Labeled Dataset
/generated/labeled_dataset.csv


Includes labels for supervised ML (0 = benign, 1 = malicious).

---

## 🛠 Example Usage

### Basic Generation
Generate 50,000 logs with 10% malicious entries:
python generator.py --count 50000 --attack_ratio 0.1



### Custom Configuration
Generate logs with specific attack types:
python generator.py
--count 100000
--attack_ratio 0.15
--attack_types "sql_injection,brute_force,xss"
--output_format json
--output_file ./data/custom_logs.json



### Time Range Specification
Generate logs for a specific date range:
python generator.py
--count 30000
--start_date "2025-01-01"
--end_date "2025-01-31"
--output_file ./data/january_logs.txt

### Mixed User Profiles
Generate logs with realistic user behavior patterns:
python generator.py
--count 75000
--user_profiles 5
--attack_ratio 0.12
--include_ueba_features
--output_format csv



### Stress Test
Generate maximum volume for performance benchmarking:
python generator.py
--count 500000
--attack_ratio 0.05
--batch_size 10000
--output_file ./data/stress_test.txt


---

## 📋 Configuration Parameters

### Core Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--count` | `int` | 10000 | Total number of logs to generate. |
| `--attack_ratio` | `float` | 0.1 | Fraction of logs that are malicious (0.0–1.0). |
| `--output_file` | `str` | `logs_sample.txt` | Output file path. |
| `--output_format` | `str` | `txt` | Output format: `txt`, `json`, or `csv`. |
| `--seed` | `int` | `None` | Random seed for reproducibility. |

### Time Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--start_date` | `str` | 7 days ago | Start timestamp (ISO-8601). |
| `--end_date` | `str` | Now | End timestamp (ISO-8601). |
| `--include_offhours` | `bool` | `True` | Include off-hours activity (realistic pattern). |

### Attack Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--attack_types` | `str` | `all` | Comma-separated attack types to inject. |
| `--obfuscate_payloads` | `bool` | `False` | Encode/obfuscate attack payloads. |
| `--payload_variation` | `int` | 3 | Number of variations per attack type. |

### Dataset Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--user_count` | `int` | 20 | Number of simulated users. |
| `--device_count` | `int` | 10 | Number of simulated devices. |
| `--include_ueba_features` | `bool` | `False` | Add UEBA-relevant fields (login times, locations). |
| `--include_labels` | `bool` | `False` | Include ground-truth labels (0/1). |

### Performance Parameters

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--batch_size` | `int` | 5000 | Batch size for memory efficiency. |
| `--num_workers` | `int` | 1 | Parallel worker threads. |
| `--compression` | `str` | `None` | Compress output: `gzip` or `None`. |

---

## 🎯 Usage Examples

### Example 1: Training Dataset
python generator.py
--count 100000
--attack_ratio 0.2
--include_labels
--include_ueba_features
--output_format csv
--output_file ./datasets/training_data.csv


### Example 2: Specific Attack Scenario
python generator.py
--count 5000
--attack_types "sql_injection"
--attack_ratio 0.8
--output_file ./datasets/sqli_attack_logs.txt


### Example 3: Reproducible Testing
python generator.py
--count 50000
--attack_ratio 0.1
--seed 42
--output_file ./datasets/test_run.json
--output_format json

### Example 4: Multi-Day Simulation
python generator.py
--count 200000
--start_date "2025-01-01"
--end_date "2025-01-07"
--attack_ratio 0.12
--include_offhours
--output_file ./datasets/week_simulation.csv
--output_format csv


---

## 📊 Output Examples

### Raw Text Output
2025-01-11T12:43:22Z | sshd | Failed password for admin from 192.168.1.45 port 51234
2025-01-11T12:44:05Z | apache2 | 203.0.113.50 GET /login.php?user=admin' OR '1'='1 HTTP/1.1 200
2025-01-11T12:45:10Z | mysql | Query: SELECT * FROM accounts WHERE username='root'; DROP TABLE users--
2025-01-11T12:46:33Z | kernel | Process /bin/bash executed with args: -c rm -rf /

text

### JSON Output
[
{
"timestamp": "2025-01-11T12:43:22Z",
"source": "192.168.1.45",
"destination": "10.0.0.10",
"username": "admin",
"event_type": "ssh_login",
"status": "failed",
"message": "Failed password",
"is_malicious": false,
"attack_type": null
},
{
"timestamp": "2025-01-11T12:44:05Z",
"source": "203.0.113.50",
"destination": "10.0.0.20",
"username": "web_user",
"event_type": "http_request",
"method": "GET",
"url": "/admin.php?id=1' OR '1'='1",
"status_code": 200,
"is_malicious": true,
"attack_type": "sql_injection"
}
]


### CSV Output (With Labels)
timestamp,source,destination,username,event_type,method,status,message,is_malicious,attack_type
2025-01-11T12:43:22Z,192.168.1.45,10.0.0.10,admin,ssh_login,N/A,failed,Failed password,0,
2025-01-11T12:44:05Z,203.0.113.50,10.0.0.20,web_user,http_request,GET,200,Request OK,1,sql_injection
2025-01-11T12:45:10Z,10.0.0.5,10.0.0.30,db_user,database_query,N/A,success,Query executed,1,command_injection


---

## 🔄 Integration with Pipeline

### 1. Direct Testing
Generate logs
python generator.py --count 50000 --attack_ratio 0.1 --output_file ./test_logs.txt

Run through parser
python log_parser_1.py --input ./test_logs.txt

Run cleaning
python clean_data_2.py --input parsed_logs.json

Feature engineering
python feature_engineering_3.py --input cleaned_logs.json

ML inference
python retrain4.py --input engineered_features.csv --mode inference

text

### 2. Automated Testing Script
from generator import LogGenerator

Initialize generator
gen = LogGenerator(
count=50000,
attack_ratio=0.1,
seed=42
)

Generate logs
logs = gen.generate(format='json')

Pass to pipeline
from log_parser_1 import LogParser
parser = LogParser()
parsed = parser.parse_batch(logs)

text

---

## ⚙️ Advanced Features

### Custom Attack Injection
python generator.py
--count 10000
--custom_attack_file ./custom_payloads.json

text

**custom_payloads.json:**
{
"attacks": [
{
"type": "custom_exploit",
"payload": "YOUR_CUSTOM_PAYLOAD_HERE",
"injection_field": "url",
"frequency": 0.05
}
]
}

text

### Behavioral Simulation
python generator.py
--count 100000
--simulate_user_behavior
--behavior_config ./user_profiles.yaml

text

### UEBA Feature Enrichment
python generator.py
--count 75000
--include_ueba_features
--add_geo_data
--add_device_fingerprints

text

---

## 🎯 Best Practices

1. **Use Seeds for Reproducibility:** Always set `--seed` for consistent testing across runs.
2. **Balance Datasets:** Use `--attack_ratio 0.1–0.2` for realistic imbalanced datasets.
3. **Include Labels:** Add `--include_labels` for supervised ML training.
4. **Test Scalability:** Use `--count 500000` to stress-test the pipeline.
5. **Vary Time Ranges:** Generate logs across multiple days for temporal pattern testing.
6. **Profile User Behavior:** Use `--user_count` and behavioral patterns for UEBA validation.

---

## 📝 Output Validation Checklist

After generation, verify:
- [ ] Log count matches `--count` parameter.
- [ ] Malicious log ratio approximately matches `--attack_ratio`.
- [ ] Timestamps are valid and within specified range.
- [ ] IPs are valid IPv4 addresses.
- [ ] Attack payloads are correctly injected.
- [ ] Output format is correctly structured (JSON valid, CSV parseable).
- [ ] No truncated or corrupted entries.

# 📄 Detailed Explanation: `generator.py`

## 📘 Overview
The `generator.py` script is a sophisticated **synthetic log generation engine** designed to create high-fidelity security datasets. Unlike simple random log generators, this tool injects **context-aware threat scenarios** (UEBA clusters) and specific attack patterns while labeling every entry with a ground truth tag (`|| gt0` for benign, `|| gt1` for malicious).

It is built to test **SIEM rules**, **User and Entity Behavior Analytics (UEBA) models**, and **Machine Learning classifiers** by providing a controlled mix of normal background noise and complex attack sequences.

---

## ✅ Core Purpose
1.  **Generate Realistic Noise:** Creates plausible background traffic for various systems (Linux, Apache, Database, Firewall, etc.).
2.  **Inject Labeled Threats:** Simulates specific attack vectors (Malware, SQLi, Exfiltration) and labels them for supervised learning.
3.  **Simulate Behavioral Anomalies (UEBA):** Generates "clusters" of related events that mimic a human attacker moving through a system (e.g., login → privilege escalation → data exfiltration).
4.  **End-to-End Pipeline Testing:** Provides the raw material needed to validate log parsers, feature engineers, and risk scoring engines.

---

## ⚙️ Code Structure & Logic

### 1. Configuration & Constants
The script begins by defining the "world" of the simulation:
*   **Entities:** Pre-defined lists of `HOSTNAMES`, `USERS`, `PROCESS_NAMES`, `USER_AGENTS`, and `BADGE_IDS` ensure consistency across different log files.
*   **Probabilities:**
    *   `PROB_KNOWN_THREAT`: 0.15% chance of a known CVE/Malware signature.
    *   `PROB_UEBA_ANOMALY`: 0.3% chance of a standalone behavioral anomaly.
    *   `PROB_INFO`: ~98.5% chance of normal, benign activity.

### 2. Helper Functions
Small utilities used to randomize data while maintaining format validity:
*   `rand_ip(public=True)`: Generates random public or private IPs.
*   `rand_timestamp()` / `rand_iso_ts()`: Creates timestamps in Syslog (`Nov 14 10:11:22`) or ISO-8601 (`2023-11-14T10:11:22Z`) formats.
*   `sometimes(p)`: Boolean helper to trigger rare random events based on probability `p`.

### 3. Baseline Log Generators
These functions generate the "bulk" of the data. They mostly produce benign (`gt0`) logs but occasionally inject a single-line anomaly (`gt1`).

| Generator Function | Log Type | Example Output |
| :--- | :--- | :--- |
| `gen_syslog_line` | System | `Nov 12 web01 sshd[222]: Failed password for root...` |
| `gen_auth_line` | Auth | `Nov 12 web01 sshd[412]: Accepted password for alice...` |
| `gen_apache_access_line` | Web | `192.168.1.5 - - "GET /login HTTP/1.1" 200 ...` |
| `gen_firewall_line` | Network | `IPTABLES: DROP IN=eth0 SRC=10.1.1.1 ...` |
| `gen_db_query_line` | Database | `postgres[99]: user=bob db=users query="SELECT *..."` |
| `gen_evtx_text` | Windows | `SECURITY EventID=4624 User=ALICE Computer=WEB01...` |

### 4. UEBA Cluster Engine (`generate_ueba_cluster`)
This is the most advanced feature. Instead of random isolated attacks, it generates **sequences** of 20–120 events representing a coherent attack narrative.

**Supported Scenarios:**
*   **Compromised Account:** Login → File Access → Sudo Attempt → Data Exfiltration.
*   **File Spike:** Rapid burst of file reads/writes/stats by a single user.
*   **Lateral Movement:** SSH connections from one internal host to multiple others.
*   **Privilege Escalation:** Configuration changes or role modifications followed by service restarts.
*   **Low & Slow Drift:** Anomalous database queries spread out over a long duration to evade rate limiting.

### 5. Main Generation Loop (`generate_file`)
For each output file (e.g., `auth.log`, `proxy.log`):
1.  **Plan Clusters:** Decides how many attack clusters to insert (e.g., 5 to 12 clusters).
2.  **Schedule Clusters:** Randomly picks start lines for these clusters so they don't overlap unnaturally.
3.  **Stream Generation:** Iterates from line 0 to `N`:
    *   If the current line index matches a **Cluster**, it writes the next step of that specific attack scenario.
    *   If not, it rolls the dice:
        *   **98.5%**: Generates a normal log line.
        *   **~1.5%**: Injects a standalone threat (Malware, CVE, or Exfiltration).
4.  **Labeling:** Appends `|| gt0` (Benign) or `|| gt1` (Malicious) to every line.

---

## 🛡️ Supported Log Types
The generator produces a wide variety of log formats to test parsing versatility:

*   **Linux/Unix:** `system.log`, `kernel.log`, `auth.log`, `secure.log`, `audit.log`, `messages.log`, `application.log`
*   **Web Server:** `apache.log`, `access.log`, `error.log`, `proxy.log`
*   **Network:** `firewall.log`, `ids.log` (Snort-like signatures)
*   **Database:** `db_query.log`, `db_transaction.log`
*   **Cloud/API:** `cloud_audit.log`, `api_request.log`, `role_change.log`
*   **Physical/IoT:** `badge_access.log`, `environmental_alerts.log` (Temp/Humidity sensors)
*   **Windows:** `security.evtx`, `system.evtx` (Simulated text format)

---

## 🚀 Usage

### Prerequisites
*   Python 3.x
*   Standard libraries only (no `pip install` required for the generator itself).

### Running the Generator
To generate the default dataset (20,000 lines per file):


### Customizing Output
You can control the volume of data and output location:


### Output Format
The generated files will look like this:
Nov 14 10:01:22 web01 sshd: Accepted password for alice from 192.168.1.45 port 51234 || gt0
Nov 14 10:05:11 web01 sshd: Failed password for root from 203.0.113.5 port 4432 || gt1
Nov 14 10:06:01 web01 sudo: alice : TTY=pts/0 ; COMMAND=/bin/cat /etc/shadow || gt1

# 📂 Detailed Explanation: `log_parser_1.py`

## 📘 High-Level Purpose
`log_parser_1.py` is a **unified log parsing and normalization engine**. It walks a directory of heterogeneous raw log files, detects each file’s log format, parses key fields using regex, normalizes timestamps into ISO-8601 UTC, and writes everything into a **single JSONL file** (`merged_logs.jsonl`) for downstream SIEM / UEBA pipelines. It also reads and preserves **ground-truth labels** (`|| gt0` / `|| gt1`) generated by `generator.py`.[file:2]

---

## 🧭 Overall Flow

1. **Input & Output**  
   - Input directory: `./logs` (configurable via `INPUT_DIR`).[file:2]  
   - Output file: `merged_logs.jsonl` (one JSON object per line).[file:2]

2. **Processing Steps**  
   - Recursively find `*.log` / `*.logs` files under `INPUT_DIR`.[file:2]  
   - Detect log type from filename (e.g., `apache_access`, `firewall`, `db_query`).[file:2]  
   - For each line:
     - Strip the `|| gt0` / `|| gt1` suffix and convert it to an integer `ground_truth` label.[file:2]  
     - Apply the appropriate regex pattern for that log type.[file:2]  
     - Normalize any timestamp field to ISO-8601 with `Z` suffix.[file:2]  
     - Emit a JSON record with unified keys like `source_file`, `raw`, `ground_truth`, `timestamp`, `event_type`, plus any fields extracted by the regex.[file:2]

3. **Result**  
   - Prints per-file stats (e.g., `[+] Parsed apache.log (apache_access)`) and a final summary of unified log count.[file:2]

---

## 🕒 Timestamp Normalization (`normalize_timestamp`)

The function `normalize_timestamp(raw_ts)` tries multiple known time formats and converts them into a **standard ISO-8601 UTC string**.[file:2]

Supported input formats:[file:2]

- Syslog: `"%b %d %H:%M:%S"` → e.g., `Nov 13 09:12:22` (no year; current year is injected).[file:2]  
- Apache access: `"%d/%b/%Y:%H:%M:%S %z"` → e.g., `13/Nov/2025:09:12:22 +0000`.[file:2]  
- EVTX plain: `"%Y-%m-%d %H:%M:%S"` → e.g., `2025-01-01 10:00:00`.[file:2]  
- ISO with microseconds: `"%Y-%m-%dT%H:%M:%S.%fZ"`.[file:2]  
- ISO without microseconds: `"%Y-%m-%dT%H:%M:%SZ"`.[file:2]

Behavior:[file:2]

- Iterates over patterns; first successful parse is returned as `dt.isoformat() + "Z"`.  
- If the format does not contain a year (`has_year=False`), the current year is injected into the parsed `datetime` before conversion.[file:2]  
- Returns `None` if none of the patterns match.[file:2]

---

## 🔍 Regex Patterns (`PATTERNS`)

The `PATTERNS` dictionary maps a **logical log type** to a compiled regex that extracts key fields using named capture groups.[file:2]

Each pattern uses `(?P<name>...)` groups so that `m.groupdict()` returns a dict of extracted fields.[file:2] Key examples:

- `syslog` – generic syslog-like lines; captures timestamp, host, process (and optional PID), and message.[file:2]  
- `apache_access` – Apache/Nginx access logs; captures client IP, raw timestamp, HTTP method, path/URL, and status.[file:2]  
- `apache_error` – Apache error logs; captures timestamp, level, PID, and message.[file:2]  
- `firewall` – iptables-like lines; extracts timestamp, source IP (`SRC`), destination IP (`DST`), protocol (`PROTO`), and ports (`SPT`, `DPT`).[file:2]  
- `ids` – IDS/IPS (Snort-style) alerts with ET signatures and source/destination IPs.[file:2]  
- `proxy` – proxy logs (e.g., Squid); extracts timestamp, host, status code, and URL.[file:2]  
- `db_query` – database query logs; captures timestamp, host, user, and SQL query string.[file:2]  
- `cloud_audit`, `api_request`, `config_change`, `role_change`, `log_management`, `log_archive` – various structured app/cloud logs with key-value patterns.[file:2]  
- `badge_access` – physical badge reader access events; extracts badge ID, door, and result (GRANTED/DENIED).[file:2]  
- `environmental` – environmental sensor logs; captures sensor name and numeric reading.[file:2]  
- `usb` – USB activity lines; targets USB serial numbers and actions.[file:2]  
- `evtx` – flattened Windows event text; captures timestamp, log type, EventID, and User.[file:2]

If a given `log_type` has no entry in `PATTERNS`, or the regex fails to match a particular line, the script still emits a record, but only with minimal fields (`source_file`, `raw`, `ground_truth`).[file:2]

---

## 🧬 File Type Detection (`detect_type`)

`detect_type(filename)` maps file names (lowercased) to logical log types, using simple substring checks.[file:2]

Examples:[file:2]

- Filenames containing `"apache"` or `"access"` → `apache_access`.  
- `"error"` → `apache_error`.  
- `"firewall"` → `firewall`.  
- `"ids"` → `ids`.  
- `"db_query"` → `db_query`.  
- `"db_transaction"` → `db_transaction`.  
- `"cloud"` → `cloud_audit`.  
- `"api"` → `api_request`.  
- `"config_change"` → `config_change`.  
- `"role_change"` → `role_change`.  
- `"management"` → `log_management`.  
- `"archive"` → `log_archive`.  
- `"badge"` → `badge_access`.  
- `"environmental"` → `environmental`.  
- `"usb"` → `usb`.  
- `"evtx"` → `evtx`.  
- Anything else defaults to `syslog`.[file:2]

This simple mapping lines up with the filenames produced by `generator.py`, ensuring that each synthetic file is parsed using the appropriate regex pattern.[file:2]

---

## 🧷 Ground Truth Extraction (`extract_ground_truth`)

Synthetic logs from `generator.py` end with a label suffix, like:`line || gt0` or `line || gt1`.[file:2]

The function `extract_ground_truth(raw_line)`:[file:2]

1. Checks if the line contains `"|| gt"`.  
2. If not present, returns `(raw_line.strip(), 0)` — default ground truth is benign.[file:2]  
3. If present, splits from the right (`rsplit("||", 1)`), producing:
   - `log_part`: the original log text (trimmed).
   - `gt_part`: e.g. `gt1` or `gt0` (trimmed).[file:2]  
4. Maps:
   - `"gt1"` → `(log_part, 1)` (malicious / suspicious).  
   - Anything else (including `"gt0"`) → `(log_part, 0)`.[file:2]

This gives the parser a clean separation between **raw log content** and **label**, which is critical for supervised ML training and evaluation.[file:2]

---

## 🧩 Line Parsing (`parse_line`)

`parse_line(line, log_type, fname)` converts one raw line into a normalized JSON-ready dict.[file:2]

Steps:[file:2]

1. **Ground Truth Extraction**  
clean_line, gt = extract_ground_truth(line)

- `clean_line`: log text without `|| gtX`.  
- `gt`: integer label 0/1.[file:2]

2. **Base Entry**  
- `clean_line`: log text without `|| gtX`.  
- `gt`: integer label 0/1.[file:2]

2. **Base Entry**  
entry = {
"source_file": fname,
"raw": clean_line,
"ground_truth": gt,
}

- `source_file`: basename of the log file (e.g., `apache.log`).  
- `raw`: original line sans label.  
- `ground_truth`: 0 or 1.[file:2]

3. **Apply Pattern**  
- Looks up `pattern = PATTERNS.get(log_type)`. If none, returns `entry` as-is.[file:2]  
- If pattern exists, runs `pattern.search(clean_line)`.  
- On a match:
  - `data = m.groupdict()` extracts named groups.  
  - `entry.update(data)` merges extracted fields into the record.[file:2]

4. **Timestamp Normalization & Event Type**  
- If `"timestamp"` was one of the extracted fields, it is normalized via `normalize_timestamp` and overwritten with ISO-8601 UTC string.[file:2]  
- Adds `entry["event_type"] = log_type` so downstream code knows which parser path was used.[file:2]

Return value: fully populated `entry` dict ready for JSON serialization.[file:2]

---

## 📁 Walking the Log Tree (`find_log_files`)

`find_log_files(base_dir=INPUT_DIR)` is a generator that recursively traverses `INPUT_DIR` using `os.walk` and yields only files ending in `.log` or `.logs`.[file:2]

This allows the system to ingest arbitrarily nested log folder structures (per-host, per-date, etc.) as long as filenames follow the expected conventions.[file:2]

---

## 📦 Unification & Output (`unify_all_logs`)

`unify_all_logs(input_dir=INPUT_DIR, output_file=OUTPUT_FILE)` orchestrates the full parsing pipeline.[file:2]

Workflow:[file:2]

1. Opens `output_file` once for writing (`merged_logs.jsonl`).  
2. Initializes a `count` of total log entries processed.[file:2]  
3. For each log file found by `find_log_files(input_dir)`:
- Derives `fname = os.path.basename(path)`.  
- Detects `log_type = detect_type(fname)`.  
- Reads file line-by-line:
  - Skips empty lines.  
  - Parses line with `parse_line(line, log_type, fname)`.  
  - Serializes the resulting dict using `json.dump(parsed, out)` and writes a newline.[file:2]  
  - Increments `count`.[file:2]  
- Prints `[+] Parsed {fname} ({log_type})` for visibility.[file:2]
4. After all files, prints a final summary:  
✅ Unified X log entries → merged_logs.jsonl
The script runs `unify_all_logs()` in the `if __name__ == "__main__":` guard, so executing the file directly will perform the full merge.[file:2]

---

## 🔗 Relationship to `generator.py`

- `generator.py` writes multiple `.log` / `.evtx`-style files into an output directory, with each line ending in `|| gt0` or `|| gt1`.[file:1][file:2]  
- `log_parser_1.py`:
- Reads those files from `./logs` (or a configured directory if you copy them there).[file:2]  
- Extracts `ground_truth` labels and structured fields (IPs, URLs, statuses, event IDs, sensors, etc.).[file:2]  
- Normalizes timestamps and unifies all entries into `merged_logs.jsonl` for downstream **cleaning, feature engineering, UEBA, ML training, and dashboarding**.[file:2]

This makes `log_parser_1.py` the **first structured stage** of the pipeline, converting raw text logs + gt labels into a machine-friendly, consistent JSON schema.[file:2]

# 🧹 Detailed Explanation: `clean_data_2.py`

## 📘 High-Level Purpose
`clean_data_2.py` takes the unified raw logs from `merged_logs.jsonl` (output of `log_parser_1.py`) and converts them into an **enriched, ML-ready dataset** in `cleaned_logs.jsonl`.[file:3]  
It is **ground-truth aware**: it understands the `ground_truth` labels (0/1), adds an ML-friendly alias `gt`, infers categories, sub-categories, severity, and a location identifier for each event.[file:3]

---

## 📥 Inputs & Outputs

- **Input file:** `INPUT_FILE = "merged_logs.jsonl"` – JSONL file with one parsed log per line.[file:3]  
- **Output file:** `OUTPUT_FILE = "cleaned_logs.jsonl"` – JSONL file with enriched records.[file:3]  

Each output record includes (at minimum):

- `raw`, `source_file`, `event_type` (from parser).[file:3]  
- `ground_truth` (int), `gt` (alias for ML).[file:3]  
- `category`, `sub_category`, `severity`, `location_id` (enrichment).[file:3]

The script is driven by `clean_logs()` and executed via `if __name__ == "__main__": clean_logs()`.[file:3]

---

## 🧱 Category & Keyword Maps

### CATEGORY_MAP
Maps **event types** (or source prefixes) to a high-level **category**:[file:3]

- `syslog`, `kernel` → `system`  
- `auth`, `secure` → `auth`  
- `apache_access`, `apache_error`, `access` → `web`  
- `firewall`, `ids`, `proxy` → `network`  
- `file_access`, `usb` → `storage`  
- `db_query`, `db_transaction` → `database`  
- `cloud_audit`, `api_request` → `cloud`  
- `config_change`, `role_change` → `config`  
- `log_management`, `log_archive` → `infra`  
- `badge_access`, `environmental` → `physical`  
- `evtx` → `windows`[file:3]

If neither `event_type` nor `source_file` prefix matches, category defaults to `"unknown"`.[file:3]

### KEYWORDS
Maps **keywords in the raw log text** to more specific **sub-categories**:[file:3]

- `"login"`, `"password"` → `authentication`  
- `"sudo"`, `"role"` → `privilege`  
- `"failed"` → `failed_login`  
- `"accepted"` → `login_success`  
- `"error"` → `error`  
- `"warning"` → `warning`  
- `"query"` → `database_query`  
- `"transaction"` → `db_transaction`  
- `"blocked"`, `"drop"` → `network_block`  
- `"ids"` → `intrusion`  
- `"usb"` → `device_activity`  
- `"file"` → `file_access`  
- `"env"` → `sensor_alert`  
- `"badge"` → `physical_access`  
- `"ueba"`, `"anomaly"` → `behavior_anomaly`  
- `"vulnerability"` → `known_threat`  
- `"detection"` → `malware_detect`  
- `"brute-force"` → `bruteforce_attempt`[file:3]

The first keyword match in the raw text determines `sub_category`; if nothing matches, `sub_category` stays `"general"`.[file:3]

---

## 📍 Location Inference (`infer_location`)

`infer_location(entry)` enriches each log with a `location_id` based on hostnames, IP ranges, cloud projects, door IDs, or sensors.[file:3]

Inputs considered:[file:3]

- `raw` (lowercased free text).  
- `host`.  
- `src_ip`, `dst_ip`.  
- `project` (for cloud logs).  
- `door` (badge access).  
- `sensor` (environmental).[file:3]

Logic:

1. **Cloud region mapping**  
   If `source_file` name contains `"cloud"`:[file:3]
   - `project` containing `"us"` → `AWS_US_EAST`  
   - `"ap"` → `AWS_AP_SOUTH`  
   - `"eu"` → `AWS_EU_CENTRAL`  
   - Else → `CLOUD_GENERIC`[file:3]

2. **Hostname-based data center zones**  
   - `host.startswith("web")` → `DC_WEB`  
   - `host.startswith("db")` → `DC_DB`  
   - `host.startswith("proxy")` → `DC_NET`  
   - `host.startswith("app")` → `DC_APP`[file:3]

3. **IP segment–based network zones**  
   - `10.0.1.x` in `src_ip` or `dst_ip` → `NET_SEGMENT_A`  
   - `10.0.2.x` → `NET_SEGMENT_B`  
   - `172.16.x.x` → `INTERNAL_DMZ`[file:3]

4. **Physical environment**  
   - If `"badge"` in `raw` or `door` present → `PHYS_<DOOR_NAME>` (spaces → `_`, uppercased, default `ENTRY`).[file:3]  
   - If `sensor` present → `ENV_<SENSOR_NAME>` uppercased.[file:3]

5. **Fallback**  
   - If `host` exists but not mapped, uses MD5 hash prefix: `HOST_<HASH6>` (first 6 hex chars of hash).[file:3]  
   - Else: `UNK`.[file:3]

This `location_id` becomes a powerful feature for UEBA and risk scoring, grouping events by logical zones (DC, network segment, cloud region, or physical area).[file:3]

---

## 🧠 Categorizer (`categorize`)

`categorize(entry)` is the core enrichment function that adds category, sub-category, severity, gt alias, and location to a log record.[file:3]

Steps:

1. **Prepare text context**  
   - `text` = `raw.lower()` (full log line).  
   - `src` = `source_file.lower()`.  
   - `evt` = `event_type.lower()`.[file:3]

2. **Category selection**  
   - First tries `CATEGORY_MAP[evt]`.  
   - If not found, falls back to `CATEGORY_MAP[src.split('.')[0]]`.  
   - If still missing, `category = "unknown"`.[file:3]

3. **Sub-category from keywords**  
   - Initializes `sub_category = "general"`.  
   - Scans `KEYWORDS` in order; the first keyword present in `text` sets the sub-category.[file:3]

4. **Base severity heuristic**  
   Before ground-truth logic, severity is inferred from text:[file:3]
   - If any of `["error", "failed", "denied", "drop", "reject"]` in text → `severity = "high"`.  
   - Else if any of `["warn", "delay", "timeout"]` in text → `severity = "medium"`.  
   - Else → `severity = "low"`.[file:3]

5. **Ground-truth–aware enrichment**  
   - Reads `gt = entry.get("ground_truth", 0)`.[file:3]  
   - Adds alias: `entry["gt"] = gt` (easier field name for ML models).[file:3]  
   - If `gt == 1` (true threat/suspicious):
     - Force `severity = "high"` regardless of text.[file:3]  
     - If `sub_category == "general"`, change to `"threat"` to ensure non-empty threat labeling.[file:3]

6. **Attach enrichment fields**  
   - `entry["category"] = category`  
   - `entry["sub_category"] = sub_category`  
   - `entry["severity"] = severity`  
   - `entry["location_id"] = infer_location(entry)`[file:3]

The enriched `entry` dict is returned, ready to be written out for downstream feature engineering.[file:3]

---

## 🔄 Cleaning Loop (`clean_logs`)

`clean_logs(input_file=INPUT_FILE, output_file=OUTPUT_FILE)` processes the entire dataset line-by-line using `tqdm` for progress.[file:3]

Workflow:

1. Opens `input_file` for reading and `output_file` for writing.[file:3]  
2. Iterates each line with `tqdm(..., desc="Categorizing logs")`.[file:3]  
3. For each line:
   - `json.loads(line)` → `entry`.  
   - Ensures `ground_truth` is an integer:
     ```
     if "ground_truth" in entry:
         entry["ground_truth"] = int(entry["ground_truth"])
     ```[file:3]
   - Calls `entry = categorize(entry)`.  
   - `json.dump(entry, outfile)` then writes `\n`.[file:3]  
   - Increments `total`.[file:3]
4. If a line is not valid JSON (`json.JSONDecodeError`), it is skipped.[file:3]  
5. After completion, prints:
✅ Cleaned X logs → cleaned_logs.jsonl

This function is invoked when the script is run directly, turning merged raw logs into a **semantically enriched, labeled, location-aware dataset** for ML/UEBA.[file:3]

---

## 🔗 Role in the Pipeline

- **Input:** `merged_logs.jsonl` from `log_parser_1.py` (already structured & timestamp-normalized, with `ground_truth`).[file:2][file:3]  
- **Output:** `cleaned_logs.jsonl`, adding:
- High-level `category` (system, web, network, database, etc.).  
- `sub_category` (authentication, malware_detect, behavior_anomaly, etc.).  
- `severity` informed by text + ground truth.  
- `gt` alias and `location_id` for UEBA and risk modeling.[file:3]

This makes `clean_data_2.py` the **semantic enrichment and cleaning stage**, bridging raw parsed logs and downstream **feature_engineering_3.py**.[file:3]

# 🔧 Detailed Explanation: `feature_engineering_3.py`

## 📘 High-Level Purpose
`feature_engineering_3.py` converts cleaned, labeled logs into **ML-ready feature sets** with:  
- Threat/UEBA flags (pattern-based, not label-leaking).  
- Encoded categorical features.  
- Time-aware UEBA features.  
- Sparse text embeddings + scaled numeric features.  
It outputs both **human-readable CSV/JSON** and **hybrid sparse matrices (X) + labels (y)** for model training.[file:4]

---

## 📥 I/O, Config & GT-Safe Design

**Config & paths:**[file:4]  
- Input: `INPUT_FILE = "cleaned_logs.csv"` (from `clean_data_2.py`).  
- Threat patterns: `threat_patterns.json` (known_threats, vulnerabilities, ueba_signals).  
- Outputs (under `output/`):
  - `features_timeaware.csv`, `features_timeaware.jsonl` – enriched tabular data.  
  - `hybrid_features_sparse.npz` – sparse feature matrix X.  
  - `hybrid_labels.npy` – label vector y.  
  - `hybrid_scaler.pkl` – `StandardScaler` for numeric features.  
  - `embedding_model_name.txt` – records vectorizer name.[file:4]

**GT-safe design:**[file:4]  
Printed banner clarifies:
- `gt`/`ground_truth` is **only** used as the target label `y`.  
- Threat detection, severity, category, UEBA features, and embeddings **do not depend on gt**, preventing label leakage.[file:4]

---

## 🧩 Threat Pattern Handling

### Loading patterns (`load_patterns`)

Reads `threat_patterns.json` into:[file:4]  
{
"known_threats": { "name": [regex1, regex2, ...], ... },
"vulnerabilities": { ... },
"ueba_signals": { ... }
}
If file is missing or invalid, falls back to empty dicts to keep pipeline robust.[file:4]

### Safe regex matching (`safe_match`)

`safe_match(patterns, text)` iterates a list of regex strings and returns `True` on first match, catching malformed regexes and ignoring errors.[file:4]

### Threat detection (`detect_threat`)

For each entry:[file:4]  
1. `raw = entry["raw"].lower()`.  
2. Search:
   - `PAT["known_threats"]` → returns `("known_threat", name)` on match.  
   - `PAT["vulnerabilities"]` → `("vulnerability", name)`.  
   - `PAT["ueba_signals"]` → `("ueba_anomaly", name)`.  
3. If no pattern matches:
   - If `severity == "high"` → `("unknown_threat", "unclassified_high_risk")`.  
   - Else → `("benign", None)`.[file:4]

Output fields added later:
- `threat_type` ∈ {`known_threat`, `vulnerability`, `ueba_anomaly`, `unknown_threat`, `benign`}.  
- `threat_subtype` = specific pattern name or `"none"`.[file:4]

---

## 🔢 Categorical Encoding

Global mutable structures:[file:4]  
- `ENCODERS = defaultdict(dict)` – per-field mapping from category string to integer ID.  
- `COUNT = defaultdict(int)` – per-field counter.

`encode(field, value)`:[file:4]  
- If `value` not seen for this `field`, assign next integer ID.  
- Returns the integer ID.  

Used to create:
- `category_id` – from `category`.  
- `sub_category_id` – from `sub_category`.  
- `severity_id` – from `severity`.  
- `location_id_num` – from `location_id`.  
- `threat_type_id` – from `threat_type`.[file:4]

This produces low-cardinality numeric encodings for downstream models.

---

## ⏱️ UEBA Time Features (`ueba_time`)

`ueba_time(df)` builds time-based behavioral features from `timestamp`:[file:4]  

1. Parse timestamps:
   - `df["datetime"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)`.  
   - Drop rows with invalid datetime.[file:4]

2. Basic time features:
   - `hour_of_day` = `0–23`.  
   - `day_of_week` = `0–6`.  
   - `is_weekend` = `day_of_week >= 5`.  
   - `is_off_hours` = hour in `[0,1,2,3,4]`.[file:4]

3. Per-user event density (if `user` column exists):[file:4]  
   - `hour_bucket` = datetime floored to the hour.  
   - Group by `["user", "hour_bucket"]` and count events → `event_count`.  
   - Merge back into main df.  
   - Compute global mean `th` = average `event_count` (fallback to 1).  
   - `ueba_burst` = `event_count > th * 5` (unusually dense activity).[file:4]

4. If no `user` column:
   - `event_count = 1`.  
   - `ueba_burst = False`.[file:4]

5. Combine:
   - `ueba_time_anomaly = is_off_hours OR is_weekend OR ueba_burst`.[file:4]

These fields feed UEBA logic and are later used as numeric features.

---

## 🏗️ Main Feature Engineering (`feature_engineer`)

`feature_engineer()` builds the enriched feature DataFrame and saves CSV/JSON.[file:4]

Steps:

1. **Load input CSV**  
df_input = pd.read_csv(INPUT_FILE)

Logs number of loaded rows.[file:4]

2. **Iterate rows & enrich**  
For each row in `df_input` (using `tqdm`):[file:4]  
- Convert row to dict `e`.  
- Ground truth (label only):
  ```
  e["gt"] = int(e.get("gt", e.get("ground_truth", 0)))
  ```[file:4]
- Threat detection (no GT usage):
  ```
  ttype, subtype = detect_threat(e)
  e["threat_type"] = ttype
  e["threat_subtype"] = subtype or "none"
  ```[file:4]
- Categorical encodings:
  ```
  e["category_id"] = encode("category", e.get("category","unknown"))
  e["sub_category_id"] = encode("sub_category", e.get("sub_category","general"))
  e["severity_id"] = encode("severity", e.get("severity","low"))
  e["location_id_num"] = encode("location_id", e.get("location_id","UNK"))
  e["threat_type_id"] = encode("threat_type", ttype)
  ```[file:4]
- Boolean ML flags:
  ```
  e["is_threat"] = int("threat" in ttype)
  e["is_ueba"]   = int("ueba" in ttype)
  e["is_vuln"]   = int("vulnerability" in ttype)
  ```[file:4]
- Append enriched dict to `rows` list.[file:4]

3. **Create DataFrame**  
df = pd.DataFrame(rows)

Logs feature-engineered row count.[file:4]

4. **UEBA time features**  
df = ueba_time(df)
df.loc[df["ueba_time_anomaly"], "is_ueba"] = 1
- Time anomalies ensure `is_ueba` is set even if text pattern didn’t tag it.[file:4]

5. **Save tabular outputs**  
- `df.to_csv(OUTPUT_CSV, index=False)`  
- `df.to_json(OUTPUT_JSON, orient="records", lines=True)`[file:4]

Returns `df` for use by `vectorize_sparse`.[file:4]

---

## 🧬 Sparse Text + Numeric Embeddings (`vectorize_sparse`)

`vectorize_sparse(df)` builds the final hybrid feature matrix X and label vector y.[file:4]

1. **Text extraction**  
texts = df["raw"].fillna("").astype(str).tolist()


2. **HashingVectorizer config**  
vectorizer = HashingVectorizer(
n_features=2**15,
alternate_sign=False,
ngram_range=(1,3),
norm="l2",
lowercase=True
)

- 2^15 (32,768) features.  
- 1–3 gram character/word n-grams (depending on tokenizer).  
- Non-negative, L2-normalized feature vectors.  
- Stateless (no fitted vocabulary to save).[file:4]

3. **Transform raw text**  
X_text = vectorizer.transform(texts)

Produces a large sparse matrix for text features.[file:4]

4. **Numeric feature list**  
NUMERIC = [
"category_id","sub_category_id","severity_id","location_id_num",
"is_threat","is_ueba","is_vuln",
"hour_of_day","day_of_week","is_weekend","is_off_hours","event_count",
]

5. **Ensure numeric columns exist**  
For each `c` in `NUMERIC`, if missing in `df`, create column filled with 0.[file:4]

6. **Scale numeric features**  
X_num = df[NUMERIC].astype(float).to_numpy()
scaler = StandardScaler()
X_num_scaled = scaler.fit_transform(X_num)
joblib.dump(scaler, SCALER_PATH)
X_num_sparse = sp.csr_matrix(X_num_scaled)
- Standardizes numeric columns to zero-mean, unit-variance.  
- Saves the scaler to reapply during inference.[file:4]

7. **Combine numeric + text**  
X_hybrid = sp.hstack([X_num_sparse, X_text]).tocsr()

This yields the final hybrid feature matrix X.

8. **Labels y (GT-only)**  
y = df["gt"].to_numpy(int)

- y is strictly the ground truth label, consistent with GT-safe design.[file:4]

9. **Persist artifacts**  
sp.save_npz(HYBRID_X, X_hybrid)
np.save(HYBRID_Y, y)
with open(MODEL_NOTE, "w") as f:
f.write(VECTORIZER_NAME)

- Saves X, y, scaler, and vectorizer name for downstream training scripts.

---

## 🔗 Role in the Full Pipeline

- **Inputs:**  
- `cleaned_logs.csv` from `clean_data_2.py` (already enriched with category, sub_category, severity, location_id, gt).[file:3][file:4]  
- `threat_patterns.json` describing known threats, vulnerabilities, UEBA signals.[file:4]

- **Outputs:**  
- Human-readable: `features_timeaware.csv` / `.jsonl`.  
- ML artifacts: sparse X (`hybrid_features_sparse.npz`), labels y (`hybrid_labels.npy`), scaler, and vectorizer metadata.[file:4]

This makes `feature_engineering_3.py` the **bridge between enriched logs and ML models**, ensuring **label-safe**, time-aware, and text-augmented feature representations suitable for both supervised detection and UEBA/anomaly modeling.[file:4]


# 🤖 Detailed Explanation: `retrain4.py`

## 📘 High-Level Purpose
`retrain4.py` is the **model training, inference, and metrics** module of the pipeline.[file:5]  
It loads feature-engineered data, trains a **CatBoost supervised classifier** using strict ground truth (GT), trains an **IsolationForest UEBA model** on numeric behavior features, runs inference for both, groups events into time-based incidents, and finally computes SOC metrics and exports them.[file:5]

---

## 🗂 Paths, Mode & Dataset Loading

### Strict GT Fast Mode
At startup it prints a banner: **“STRICT GT MODE ENABLED (FAST MODE)”**, indicating:[file:5]

- Uses **GT labels directly**, no extra regex/heuristics for labels.  
- Optimized for **40–65% faster** training and inference.  

### Key Paths
All under `OUTPUT_DIR = "output"`:[file:5]

- `FEATURES_CSV` → `features_timeaware.csv` (from `feature_engineering_3.py`).  
- `HYBRID_X_PATH` → `hybrid_features_sparse.npz` (sparse hybrid features X).  
- `SCALER_NUMERIC_PATH` → `hybrid_scaler.pkl` (numeric scaler, reused for UEBA).  
- `CLASSIFIER_PATH` → `catboost_classifier.cbm` (saved CatBoost model).  
- `UEBA_PATH` → `isolation_forest.joblib` (saved UEBA model).  
- `AUG_CSV` → `features_augmented_full_ml.csv` (features + predictions).  
- `METRICS_JSON` / `METRICS_CSV` → SOC metrics summaries.[file:5]

### Loading Feature Dataset
1. `df = pd.read_csv(FEATURES_CSV, low_memory=False)`.  
2. Parses `timestamp` to UTC datetime:  
df["datetime"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
df = df[df["datetime"].notna()].reset_index(drop=True)

3. Loads sparse hybrid matrix:  
X_hybrid = sp.load_npz(HYBRID_X_PATH)

4. Validates row alignment: `X_hybrid.shape[0]` must equal `len(df)` or it aborts with a mismatch error.[file:5]

---

## 🎯 Ground Truth & Numeric Feature Setup

### GT Label Application
- Sets `df["label"] = df["gt"].astype(int)`.[file:5]  
- `y = df["label"].to_numpy(int)` is the **only supervised target**.[file:5]  
- Prints GT distribution using `Counter(y)` for transparency (class balance).[file:5]

### Numeric Feature Matrix for UEBA
Defines numeric columns:[file:5]

NUMERIC = [
"category_id", "sub_category_id", "severity_id",
"location_id_num", "hour_of_day", "day_of_week",
"is_weekend", "is_off_hours", "event_count", "gt"
]
X_numeric = df[NUMERIC].astype(float).to_numpy()


- These act as **behavioral / contextual features** for UEBA and can also inform later analysis.[file:5]

---

## ⚖️ Class Balancing (Supervised)

To handle class imbalance for CatBoost training:[file:5]

1. Compute indices:
pos_idx = np.where(y == 1)
neg_idx = np.where(y == 0)
if len(pos_idx) == 0:
raise SystemExit("❌ No positives in GT")


2. **Upsampling strategy (fast)**:[file:5]
- If positives are fewer than negatives:
  ```
  pos_up = rng.integers(0, len(pos_idx), size=len(neg_idx))
  train_idx = np.concatenate([neg_idx, pos_idx[pos_up]])
  ```
  → Upsamples positive class to match negative count.  
- Else: use all indices (already balanced or positive-heavy).  

3. Shuffle `train_idx`, then:
X_bal = X_hybrid[train_idx]
y_bal = y[train_idx]

Prints balanced distribution with `Counter(y_bal)`.[file:5]

This yields a **balanced training subset** while preserving the full test space for metrics.

---

## 🐱 CatBoost Classifier Training

### Training Configuration
Creates a `CatBoostClassifier` tuned for speed:[file:5]

clf = CatBoostClassifier(
iterations=220, # reduced from 350
depth=6, # shallower trees → faster
learning_rate=0.07,
loss_function="Logloss",
verbose=False,
random_seed=42,
thread_count=-1, # all CPU cores
border_count=32 # fewer bins → faster, minimal accuracy hit
)

Trained on the balanced subset:[file:5]
clf.fit(Pool(X_bal, y_bal))
clf.save_model(CLASSIFIER_PATH)


This model outputs **binary predictions** and **threat probabilities** for each event.

---

## 🧠 UEBA Isolation Forest Training

### Numeric Scaling & Scaler Reuse
Before IsolationForest training, numeric features are scaled:[file:5]

1. Attempts to load existing scaler:
scaler_num = joblib.load(SCALER_NUMERIC_PATH)
if scaler_num.n_features_in_ != X_numeric.shape:​
force_retrain = True
Falls back to retraining if mismatch or load failure.

2. If retrain needed or scaler missing:
scaler_num = StandardScaler().fit(X_numeric)
joblib.dump(scaler_num, SCALER_NUMERIC_PATH)

3. Applies transformation:
X_num_scaled = scaler_num.transform(X_numeric)


### Training the IsolationForest
- Uses **only normal (label=0) events** as baseline:[file:5]
normal_idx = np.where(y == 0)
sample = rng.choice(normal_idx, size=min(25000, len(normal_idx)), replace=False)

- Trains:
iso = IsolationForest(
n_estimators=80, # reduced from 160
contamination=0.012,
random_state=42,
n_jobs=-1
)
iso.fit(X_num_scaled[sample])
joblib.dump(iso, UEBA_PATH)


This model captures **unsupervised anomalies** based on behavior and context, independently from GT labels.[file:5]

---

## 📊 Inference: Supervised + UEBA

After training both models, the script runs full-dataset inference.[file:5]

### CatBoost Predictions
df["pred_label"] = clf.predict(Pool(X_hybrid)).astype(int)
df["pred_prob"] = clf.predict_proba(Pool(X_hybrid))[:, 1]
- `pred_label`: binary predicted threat/benign.  
- `pred_prob`: predicted probability of being malicious.[file:5]

### UEBA Anomaly Scores
u = iso.predict(X_num_scaled)
df["ueba_flag"] = (u == -1).astype(int) # 1 = anomaly
df["ueba_score"] = iso.decision_function(X_num_scaled)
- `ueba_flag`: isolation-based anomaly indicator.  
- `ueba_score`: anomaly score (lower → more anomalous).[file:5]

### Save Augmented Dataset
All enriched features + predictions are saved to:

df.to_csv(AUG_CSV, index=False)


This file feeds later risk scoring and dashboarding modules.

---

## 📦 Incident Grouping (1-Hour Windows)

To support SOC workflows, events are grouped into **time-based incidents**.[file:5]

1. Sort by time:
df = df.sort_values("datetime").reset_index(drop=True)
ts = df["datetime"].view("int64") // 1_000_000_000 # seconds since epoch

2. Sliding window clustering:
- Start first incident window at `boundary = ts.iloc[0] + INCIDENT_WINDOW_SECONDS` (3600 seconds).  
- Iterate `(i, t)` over timestamps:
  - If `t <= boundary`: append index `i` to `current` incident.  
  - Else: close current, start new incident with `[i]` and move boundary.[file:5]
- After loop, append last `current` if non-empty.

Result: `incidents` is a list of lists, each representing indices belonging to a 1-hour window incident.[file:5]

---

## 📈 SOC Metrics Computation

Using GT vs predictions, the script computes classic detection metrics plus UEBA stats.[file:5]

### Confusion Matrix Components
y_true = df["label"].to_numpy(int)
y_pred = df["pred_label"].to_numpy(int)

tp = int(((y_pred == 1) & (y_true == 1)).sum())
tn = int(((y_pred == 0) & (y_true == 0)).sum())
fp = int(((y_pred == 1) & (y_true == 0)).sum())
fn = int(((y_pred == 0) & (y_true == 1)).sum())


### Metrics Dictionary
metrics = {
"event_count": len(df),
"tp": tp, "tn": tn, "fp": fp, "fn": fn,
"false_positive_rate": fp / (fp + tn) if (fp + tn) else 0,
"false_negative_rate": fn / (fn + tp) if (fn + tp) else 0,
"alert_volume": int((y_pred == 1).sum()),
"ueba_anomaly_count": int(df["ueba_flag"].sum()),
"anomaly_per_day": round(
int(df["ueba_flag"].sum()) /
max(1, (df["datetime"].max() - df["datetime"].min()).days),
4
),
"incident_count": len(incidents),
}


- `event_count`: total events evaluated.  
- `alert_volume`: number of classifier alerts.  
- `ueba_anomaly_count`: number of UEBA-flagged anomalies.  
- `anomaly_per_day`: normalized UEBA anomaly rate.  
- `incident_count`: total 1-hour incident buckets.[file:5]

### Export Metrics
Saved both as JSON and CSV:[file:5]

json.dump(metrics, open(METRICS_JSON, "w"), indent=2)
pd.DataFrame([metrics]).to_csv(METRICS_CSV, index=False)

Finally prints the metrics and a completion message:  
**“🎉 STRICT-GT FAST PIPELINE — COMPLETE!”** with the JSON metrics dump.[file:5]

---

## 🔗 Role in the Overall Pipeline

- **Inputs:**  
  - `features_timeaware.csv` and `hybrid_features_sparse.npz` from `feature_engineering_3.py`.[file:4][file:5]

- **Core responsibilities:**  
  - Apply GT labels as training targets (strict GT mode).  
  - Balance data and train a fast **CatBoost classifier**.  
  - Train an **IsolationForest UEBA** model on scaled numeric features.  
  - Run inference for both models across all events.  
  - Group events into time-based incidents.  
  - Compute and export SOC-ready metrics and an augmented feature file.[file:5]

This file is the **ML heart** of the system, turning engineered features into operational detection models and measurable SOC outcomes.[file:5]

# 🔥 Detailed Explanation: `risK_score5.py`

## 📘 High-Level Purpose
`risK_score5.py` is the **Vanguard Advanced Risk Engine** that fuses ML outputs, UEBA anomaly strength, threat-intel pattern matches, and vulnerability/lateral-movement signals into a single **risk_score (0–100)** per event.[file:6]  
It consumes the augmented features from `retrain4.py`, reuses the CatBoost and IsolationForest models, and outputs a risk-enhanced CSV for dashboards and SOC workflows.[file:6]

---

## 🗂 Paths, Inputs & Outputs

**Configured paths (under `output/`):**[file:6]

- Input baseline: `AUG_CSV = "output/features_augmented_full_ml.csv"` – events + predictions from `retrain4.py`.  
- Output: `OUT_CSV = "output/features_augmented_with_risk.csv"` – same rows with risk columns added.  
- Supporting artifacts:
  - `HYBRID_X_PATH = "output/hybrid_features_sparse.npz"` – sparse features for CatBoost.  
  - `MODEL_PATH = "output/catboost_classifier.cbm"` – trained classifier.  
  - `UEBA_PATH = "output/isolation_forest.joblib"` – UEBA model.  
  - `SCALER_PATH = "output/hybrid_scaler.pkl"` – numeric scaler (auto-healed if layout changes).  
  - `PATTERN_FILE = "threat_patterns.json"` – threat intel and vulnerability regex patterns.[file:6]

**CLI entrypoint:**[file:6]
python risK_score5.py --in output/features_augmented_full_ml.csv --out output/features_augmented_with_risk.csv

Arguments `--in` and `--out` are optional, with defaults as above.[file:6]

---

## ⚖️ Risk Model Ingredients & Weights

The engine defines tunable weights `W`:[file:6]

W = {
"model_prob": 1.30, # CatBoost threat probability
"ueba": 1.10, # UEBA anomaly magnitude
"ti": 1.50, # Threat intel hits (known threat patterns)
"vuln": 0.90, # Vulnerability pattern matches
"lateral": 0.75 # Lateral movement indicators
}


Helper functions:[file:6]

- `sigmoid(x)` – squashes fused signal into (0,1).  
- `entropy_boost(p)` – increases risk when model is **uncertain** (p near 0.5).  
- `normalize(x)` – min–max normalizes an array to [0,1] (fallback to zeros if constant).[file:6]

Final risk formula (per event):[file:6]

\[
\text{fused} = W_{\text{model_prob}}\cdot p_{\text{model}} + W_{\text{ueba}}\cdot \text{ueba\_norm} + W_{\text{ti}}\cdot \mathbb{1}_{\text{TI}} + W_{\text{vuln}}\cdot \mathbb{1}_{\text{vuln}} + W_{\text{lateral}}\cdot \mathbb{1}_{\text{lat}} + 0.35 \cdot H(p_{\text{model}})
\]

\[
\text{risk\_score} = \text{sigmoid}(\text{fused}) \times 100
\]

Where \(H(p)\) is the entropy from `entropy_boost` and the indicator terms are 0/1 flags.[file:6]

---

## 🧩 Threat Patterns, TI & Vulnerability Matching

Inside `compute_risk(df)` the engine first loads threat intel patterns:[file:6]

1. **Load patterns:**
if os.path.exists(PATTERN_FILE):
PAT = json.load(open(PATTERN_FILE))
else:
PAT = {"known_threats": {}, "vulnerabilities": {}}
2. **Compile regex lists:**
- `TI_RE`: all regexes from `PAT["known_threats"].values()`.  
- `VULN_RE`: all regexes from `PAT["vulnerabilities"].values()`.  
- `LAT_RE`: hard-coded lateral movement indicators:
  `["psexec","wmic","smbclient","rpcclient","pass the hash","rdesktop"]`.[file:6]

3. **Vectorized matching on `raw` text:**
raw = df["raw"].fillna("").astype(str).to_numpy()
ti = np.array([1 if any(rx.search(r) for rx in TI_RE) else 0 for r in raw])
vuln = np.array([1 if any(rx.search(r) for rx in VULN_RE) else 0 for r in raw])
lat = np.array([1 if any(rx.search(r) for rx in LAT_RE) else 0 for r in raw])

- `ti`   → threat intel (known threat) matches.  
- `vuln` → vulnerability pattern matches.  
- `lat`  → lateral movement indicators.[file:6]

These binary arrays are later fed into the fused risk formula.

---

## 🤖 Reusing CatBoost & Hybrid Features

Risk computation always uses **fresh CatBoost inference on X_hybrid** to avoid stale probabilities:[file:6]

1. **Load hybrid features & model:**
X_hybrid = sp.load_npz(HYBRID_X_PATH)
clf = CatBoostClassifier()
clf.load_model(MODEL_PATH)

2. **Compute probabilities:**
model_prob = clf.predict_proba(Pool(X_hybrid))[:, 1]
model_prob = np.clip(model_prob, 0, 1)

- This gives a calibrated probability per event of being malicious or suspicious.  
- Values are clipped to [0,1] for numerical stability in later steps.[file:6]

---

## 🧠 UEBA Anomaly Magnitude

The engine converts UEBA anomaly scores from the IsolationForest into a normalized anomaly feature.[file:6]

1. **Load UEBA model:**
iso = joblib.load(UEBA_PATH)

2. **Define numeric feature set (aligned with strict-GT pipeline):**
NUMERIC = [
"category_id","sub_category_id","severity_id",
"location_id_num","hour_of_day","day_of_week",
"is_weekend","is_off_hours","event_count","gt"
]
for c in NUMERIC:
if c not in df:
df[c] = 0
X_num = df[NUMERIC].astype(float).to_numpy()


3. **Scaler auto-healing:**
- Attempts to load an existing `StandardScaler` from `SCALER_PATH`.  
- If missing or `n_features_in_` does not match `X_num.shape[1]`, retrains a new scaler on `X_num` and overwrites `SCALER_PATH`.[file:6]
if retrain_scaler:
scaler = StandardScaler().fit(X_num)
joblib.dump(scaler, SCALER_PATH)
X_scaled = scaler.transform(X_num)


4. **Compute UEBA scores:**
iso_raw = iso.decision_function(X_scaled) # higher = more normal
iso_inverted = -iso_raw # higher = more anomalous
ueba_norm = normalize(
RobustScaler().fit_transform(iso_inverted.reshape(-1,1)).flatten()
)

- IsolationForest returns higher scores for normal data; inverting them makes higher = more anomalous.  
- `RobustScaler` reduces influence of extreme outliers, then min–max normalization maps it to [0,1].[file:6]

This `ueba_norm` array forms the UEBA component in the fused risk signal.

---

## 🧮 Fused Nonlinear Risk Computation

Once all components are computed (`model_prob`, `ueba_norm`, `ti`, `vuln`, `lat`), the engine builds the final risk score:[file:6]

1. **Entropy term:**
ent = entropy_boost(model_prob)

- Peaks when `model_prob ≈ 0.5` (uncertain), lower near 0 or 1.[file:6]

2. **Linear fusion with weights:**
fused = (
W["model_prob"] * model_prob +
W["ueba"] * ueba_norm +
W["ti"] * ti +
W["vuln"] * vuln +
W["lateral"] * lat +
0.35 * ent
)


3. **Sigmoid + scaling to 0–100:**
risk = sigmoid(fused) * 100

- Converts unbounded fused scores into a human-friendly risk score.[file:6]

4. **Append risk columns:**
df["risk_score"] = risk.round(2)
df["risk_model_prob"] = (model_prob * 100).round(2)
df["risk_ueba_norm"] = (ueba_norm * 100).round(2)
df["risk_ti_match"] = ti
df["risk_vuln"] = vuln
df["risk_lateral"] = lat

- `risk_score`: final fused risk 0–100.  
- `risk_model_prob`: CatBoost probability scaled to %.  
- `risk_ueba_norm`: UEBA anomaly strength scaled to %.  
- `risk_ti_match`, `risk_vuln`, `risk_lateral`: 0/1 flags for contributing components.[file:6]

These fields give analysts a decomposed view of **why** an event is high-risk.

---

## 🚀 Main Entry Point (`main()`)

`main()` wires everything together:[file:6]

1. Parse CLI args:
parser = argparse.ArgumentParser(description="Vanguard Advanced Risk Engine")
parser.add_argument("--in", dest="infile", default=AUG_CSV)
parser.add_argument("--out", dest="outfile", default=OUT_CSV)
args = parser.parse_args()


2. Load augmented ML dataset:
df = pd.read_csv(args.infile, low_memory=False)


3. Compute risk:
df = compute_risk(df)


4. Save risk-enhanced CSV:
df.to_csv(args.outfile, index=False)
print("\n✅ Saved risk-enhanced dataset →", args.outfile)


This makes `risK_score5.py` the **fusion and risk-layer** of the pipeline, taking all upstream intelligence (supervised ML, UEBA, TI, vulnerability patterns, and GT-safe features) and delivering a single, interpretable risk surface suitable for dashboards, alerts, and automated response workflows.[file:6]

# 🧠 Detailed Explanation: `shap6.py`

## 📘 High-Level Purpose
`shap6.py` is the **Vanguard SHAP Explainer** for the CatBoost classifier used in the strict-GT pipeline.[file:7]  
It computes SHAP values over the **hybrid sparse feature matrix** and helps SOC analysts understand **why** a given event received a particular threat probability, either for a single event or for a sampled batch.[file:7]

---

## 🗂 Paths & Inputs

Configured paths (under `output/`):[file:7]

- `MODEL_PATH` → `catboost_classifier.cbm` – trained CatBoost model.  
- `HYBRID_X` → `hybrid_features_sparse.npz` – sparse hybrid feature matrix (numeric + text hashes).  
- `AUG_CSV` → `features_augmented_full_ml.csv` – augmented dataframe with raw logs, predictions, UEBA, etc.  
- `SHAP_OUT` → `shap_output.parquet` – default SHAP output file (used if `--out` not overridden).  
- `FEATURE_NAMES_PATH` → `hybrid_feature_names.json` – optional mapping from feature index → human-readable name.[file:7]

The script prints a banner describing capabilities and confirms strict-GT compatibility.[file:7]

---

## 🔧 Loader Helper (`load_all`)

`load_all()` centralizes loading of all required artifacts:[file:7]

1. **CatBoost model:**
model = CatBoostClassifier()
model.load_model(MODEL_PATH)


Fails fast if the model file is missing.[file:7]

2. **Sparse feature matrix:**
import scipy.sparse as sp
X_sparse = sp.load_npz(HYBRID_X)


Represents the same features used in training (numeric + HashingVectorizer text features).[file:7]

3. **Augmented dataframe:**
df = pd.read_csv(AUG_CSV, low_memory=False)


Used for context (e.g., raw log previews) and to ensure row alignment.[file:7]

4. **Optional feature names:**
feature_names = None
if os.path.exists(FEATURE_NAMES_PATH):
feature_names = json.load(open(FEATURE_NAMES_PATH))


If present, allows mapping SHAP indices to descriptive feature names (e.g., `cat:severity_id`, `txt:ngram=...`).[file:7]

5. **Row consistency check:**
if X_sparse.shape != len(df):
raise SystemExit("❌ Row mismatch ...")


Guarantees that each SHAP vector aligns with the correct event row.[file:7]

Returns `(model, X_sparse, df, feature_names)`.[file:7]

---

## 📊 Core SHAP Computation (`compute_shap_sparse`)

`compute_shap_sparse(model, X_sparse, indices)` computes SHAP values for a given list of event indices:[file:7]

1. **Subselect rows:**
X_sel = X_sparse[indices]
pool_sel = Pool(X_sel)

Uses CatBoost’s `Pool` wrapper for sparse matrices.[file:7]

2. **Prediction probabilities:**
preds = model.predict_proba(pool_sel) # shape (n, 2)
pred_probs = preds[:, 1].astype(float) # probability of class 1


3. **SHAP values from CatBoost:**
shap_vals = model.get_feature_importance(data=pool_sel, type="ShapValues")

- CatBoost returns an array of shape `(n_samples, n_features + 1)`.  
- The last column is the **base value** (expected model output).  
- The first `n_features` columns are SHAP contributions per feature.[file:7]

4. **Split base and feature contributions:**
base_vals = shap_vals[:, -1].astype(float)
shap_arr = shap_vals[:, :-1].astype(float)

- `base_vals[i]` = baseline log-odds or probability (depending on model config).  
- `shap_arr[i]` = SHAP vector for event `i`.[file:7]

5. **Build output rows:**
For each index:
{
"event_index": int(idx),
"base_value": float(base_vals[i]),
"pred_prob": float(pred_probs[i]),
"shap_vector": shap_arr[i].tolist()
}

Returns a DataFrame with one row per explained event.[file:7]

This structure is convenient for storage (CSV/Parquet) and for feeding into downstream visualizers.

---

## 🧾 Human-Readable SHAP Summary (`pretty_print_shap_vector`)

`pretty_print_shap_vector(shap_vec, feature_names=None, top_k=12)` prints the **top contributing features by absolute SHAP value**:[file:7]

1. Sorts features:
pairs = sorted(
enumerate(shap_vec),
key=lambda x: abs(x),​
reverse=True
)[:top_k]

2. For each `(feat_idx, val)`:
- Default name: `Feature[<index>]`.  
- If `feature_names` exists and covers this index, use that instead.  
- Prints in aligned format with sign:
  ```
  feature_name                          → +0.123456
  ```[file:7]

This gives SOC analysts a quick view of **which features pushed the probability up or down** for a given event.

---

## 🖥️ CLI Usage & Modes (`main`)

`main()` implements two primary modes: **single event explanation** and **batch sample explanation**.[file:7]

### Arguments
- `--event-index IDX` – explain SHAP for a **single event** by DataFrame index.[file:7]  
- `--sample N` – explain SHAP for a **random sample of N events**.[file:7]  
- `--out FILE` – save SHAP results to `.parquet` or `.csv` (format chosen by extension).[file:7]  
- `--max-sample` – safety cap for batch explanations (default 500).[file:7]

### Single Event Mode
1. Validate index range `[0, n-1]`.  
2. Print raw log preview (first 400 chars) if `raw` column exists:  
print("raw (preview):", str(df.at[idx, "raw"])[:400])

3. Call `compute_shap_sparse(..., [idx])`, get one-row DataFrame.[file:7]  
4. Call `pretty_print_shap_vector` with `top_k=20` to show detailed contributors.[file:7]  
5. If `--out` is provided, save the SHAP row (parquet or CSV) and print path.[file:7]

### Batch Sample Mode
1. Determine sample size:
sample_n = min(args.sample, n)
if sample_n > args.max_sample: sample_n = args.max_sample

2. Sample event indices:
indices = df.sample(sample_n, random_state=42).index.tolist()

3. Compute SHAP for all sampled events, get `out_df`.[file:7]  
4. For the first up to 3 events, print:
- Event index and predicted probability.  
- Top 10 SHAP features via `pretty_print_shap_vector`.[file:7]
5. If `--out` supplied, save full `out_df` to parquet/CSV; otherwise print a reminder to use `--out` for persistence.[file:7]

### No Arguments
If neither `--event-index` nor `--sample` is provided, prints a short help message showing the two usage modes and exits.[file:7]

---

## 🔗 Role in the Overall Pipeline

- **Upstream dependencies:**
- CatBoost classifier trained in `retrain4.py` and saved as `catboost_classifier.cbm`.[file:5][file:7]  
- Hybrid sparse feature matrix and augmented CSV generated by `feature_engineering_3.py` and `retrain4.py`.[file:4][file:5][file:7]

- **Value for SOC & ML Ops:**
- Provides **event-level explainability**: which features drove risk for a specific alert.  
- Supports **batch explainability** for model audits and tuning.  
- Integrates with optional feature-name maps for interpretable text and category features.[file:7]

This makes `shap6.py` the **explainability layer** of the SIEM/UEBA system, turning opaque CatBoost predictions into transparent, defensible evidence for SOC analysts and compliance requirements.[file:7]


# 📊 Detailed Explanation: `dashboard7.py`

## 📘 High-Level Purpose
`dashboard7.py` is the **Vanguard SOC ML Dashboard** built with Streamlit, providing SOC analysts with an interactive visualization of the full pipeline outputs.[file:8]  
It displays KPIs, timelines, risk distributions, UEBA heatmaps, event explorers, and integrates SHAP explainability – all from the augmented datasets produced by upstream modules.[file:8]

---

## 🗂 Paths & Data Sources

**Primary data sources (under `output/`):**[file:8]

- `AUG_RISK_CSV` → `features_augmented_with_risk.csv` (preferred, from `risK_score5.py`).  
- `AUG_CSV_FALLBACK` → `features_augmented_full_ml.csv` (from `retrain4.py` if risk CSV missing).  
- `METRICS_JSON` → `metrics_report_full_ml.json` (SOC metrics from `retrain4.py`).  
- `SHAP_SCRIPT` → `shap6.py` (called via subprocess for on-demand explainability).[file:8]

**Smart fallback loading** via `@st.cache_data(ttl=60)`:
if os.path.exists(AUG_RISK_CSV):
df = pd.read_csv(AUG_RISK_CSV)
elif os.path.exists(AUG_CSV_FALLBACK):
df = pd.read_csv(AUG_CSV_FALLBACK)
else:
st.error("❌ No augmented dataset found.")

Cached for 60 seconds to balance freshness and performance.[file:8]

---

## 🎨 Streamlit Layout & Theme

**Wide layout configuration:**
st.set_page_config(layout="wide", page_title="Vanguard SOC Dashboard")


**Optional dark mode toggle** in sidebar:
dark_mode = st.sidebar.checkbox("🌙 Dark Mode", value=True)

Applies custom CSS for dark theme styling when enabled.[file:8]

---

## 📈 Top-Level KPIs (5-Column Metrics)

Main title: **"🔰 Vanguard — SOC ML Dashboard"**

Five key performance indicators using `st.columns(5)`:[file:8]

| Column | Metric | Data Source | Fallback |
|--------|--------|-------------|----------|
| **K1** | Total Events | `len(df)` | Always available |
| **K2** | Model Alerts | `df[pred_label].sum()` | "N/A" if no prediction column |
| **K3** | UEBA Anomalies | `df[ueba_flag].sum()` or `df[is_ueba].sum()` | Always computed |
| **K4** | Avg Risk Score | `df[risk_score].mean()` | "N/A" if no risk column |
| **K5** | Top Severity | `df[severity].mode()` | "N/A" if no severity column |

**Column auto-detection** finds `pred_label`, `pred_prob`, `risk_score`, and `severity` dynamically.[file:8]

---

## 📅 Timeline & Risk Distribution (Split Layout)

**Left column (3:2 ratio) – Timeline view:**
1. **Event Timeline**: Line chart of daily event volume:
df["date_only"] = pd.to_datetime(df["datetime"]).dt.date
daily = df.groupby("date_only").size()
fig = px.line(daily, x="date_only", y="count")

2. **Top Source IPs (Alerts)**: Top 20 `src_ip` for predicted alerts (`pred_label == 1`).[file:8]

**Right column – Risk analytics:**
1. **Risk Score Distribution**: Histogram of `risk_score` (50 bins) if available.
2. **High-Risk Events Table**: Top 10 events by `risk_score` descending, showing `datetime`, `src_ip`, `host`, predictions, risk, and `raw` preview.[file:8]

---

## 🔥 UEBA Heatmap

**Day-of-week × Hour-of-day heatmap** for UEBA anomalies:
if "ueba_flag" in df.columns and "hour_of_day" in df.columns:
heat = df[df["ueba_flag"] == 1].groupby(["day_of_week", "hour_of_day"]).size()
heat_pivot = heat.pivot(index="day_of_week", columns="hour_of_day", values="count")
fig3 = px.imshow(heat_pivot, title="UEBA Activity Heatmap")

Visualizes temporal patterns in anomalous behavior (weekends, off-hours spikes).[file:8]

---

## 🔎 Interactive Event Explorer

**Filterable event table** with real-time filtering:

**Filters (3-column expander):**
- `src_ip` text filter (regex `str.contains`).  
- `host` text filter.  
- `Minimum Risk` slider (0–100).[file:8]

**Dynamic columns** (always available first, predictions/risk if present):
explore_cols = ["datetime", "src_ip", "host", "raw"]
if label_col: explore_cols.append(label_col)
if prob_col: explore_cols.append(prob_col)
if risk_col: explore_cols.append(risk_col)



**Features:**
- Real-time filtering on all events.  
- Sorted by `datetime` descending.  
- Limited to top 500 rows for performance.  
- Full `raw` log text visible for investigation.[file:8]

---

## 🧠 Integrated SHAP Explainability

**On-demand SHAP computation** via subprocess integration with `shap6.py`:
ev_idx = st.number_input("Event index", min_value=0, max_value=len(df)-1)
if st.button("Compute SHAP Explanation"):
cmd = ["python3", SHAP_SCRIPT, "--event-index", str(ev_idx)]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
st.text(res.stdout)


**Error handling:**
- Checks if `shap6.py` exists.  
- 35-second timeout to prevent hangs.  
- Displays both stdout (SHAP output) and stderr (errors).[file:8]

**Caption tip** suggests computing full SHAP samples offline for better performance.

---

## 🔗 Data Flow & Dependencies

**Pipeline integration** – consumes outputs from:[file:8]

1. `risK_score5.py` → `features_augmented_with_risk.csv` (risk scores) **[preferred]**  
2. `retrain4.py` → `features_augmented_full_ml.csv` (ML predictions + UEBA) **[fallback]**  
3. `retrain4.py` → `metrics_report_full_ml.json` (SOC metrics)  
4. `shap6.py` → on-demand event explainability  

**Robustness features:**
- Graceful fallbacks between risk-enhanced vs ML-only datasets.  
- Column auto-detection for predictions, probabilities, risk, severity.  
- Cached data loading (`@st.cache_data(ttl=60)`) for performance.  
- Comprehensive error messages when prerequisites missing.[file:8]

---

## 🚀 Usage

**Prerequisites:** Run the full ML pipeline (`main.py`) to generate required CSVs and JSONs.

**Launch dashboard:**
streamlit run dashboard7.py


**Key interactions:**
1. **KPIs** show pipeline health at a glance.  
2. **Timeline + Risk** reveal temporal and severity patterns.  
3. **UEBA Heatmap** spots off-hours/weekend anomalies.  
4. **Event Explorer** drills into specific IPs, hosts, or risk thresholds.  
5. **SHAP button** explains model decisions for any event index.[file:8]

This makes `dashboard7.py` the **capstone visualization layer**, transforming complex ML outputs into actionable SOC intelligence with zero configuration.
