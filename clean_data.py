#!/usr/bin/env python3

import json
import re
from tqdm import tqdm
import hashlib

INPUT_FILE = "merged_logs.jsonl"
OUTPUT_FILE = "cleaned_logs.jsonl"

print("""
GT-AWARE ENRICHMENT ENABLED
-------------------------------------------------
This version of the cleaner now understands logs
that contain ground_truth labels (gt0 / gt1).

Enhancements added:
- Copies 'ground_truth' from merged logs as integer.
- Adds a duplicate ML-friendly field 'gt'.
- If gt == 1:
    → severity is auto-upgraded to HIGH
    → sub_category adjusted to intrusion/threat
- Everything else stays unchanged.

This produces a fully enriched, ML-ready dataset.
-------------------------------------------------
""")

# ---------- Category map ----------
CATEGORY_MAP = {
    "syslog": "system", "kernel": "system",
    "auth": "auth", "secure": "auth",
    "apache_access": "web", "apache_error": "web", "access": "web",
    "firewall": "network", "ids": "network", "proxy": "network",
    "file_access": "storage", "usb": "storage",
    "db_query": "database", "db_transaction": "database",
    "cloud_audit": "cloud", "api_request": "cloud",
    "config_change": "config", "role_change": "config",
    "log_management": "infra", "log_archive": "infra",
    "badge_access": "physical", "environmental": "physical",
    "evtx": "windows"
}

# ---------- Keyword map ----------
KEYWORDS = {
    "login": "authentication", "password": "authentication", "sudo": "privilege",
    "role": "privilege", "failed": "failed_login", "accepted": "login_success",
    "error": "error", "warning": "warning", "query": "database_query",
    "transaction": "db_transaction", "blocked": "network_block", "drop": "network_block",
    "ids": "intrusion", "usb": "device_activity", "file": "file_access",
    "env": "sensor_alert", "badge": "physical_access",
    "ueba": "behavior_anomaly", "anomaly": "behavior_anomaly",
    "vulnerability": "known_threat", "detection": "malware_detect",
    "brute-force": "bruteforce_attempt"
}

# ---------- Location inference ----------
def infer_location(entry):
    raw = (entry.get("raw") or "").lower()
    host = (entry.get("host") or "").lower()
    src_ip = entry.get("src_ip", "")
    dst_ip = entry.get("dst_ip", "")
    project = entry.get("project", "")
    door = entry.get("door", "")
    sensor = entry.get("sensor", "")

    # Cloud region mapping
    if "cloud" in entry.get("source_file", "").lower():
        if "us" in project: return "AWS_US_EAST"
        if "ap" in project: return "AWS_AP_SOUTH"
        if "eu" in project: return "AWS_EU_CENTRAL"
        return "CLOUD_GENERIC"

    # Hostname map
    if host.startswith("web"): return "DC_WEB"
    if host.startswith("db"): return "DC_DB"
    if host.startswith("proxy"): return "DC_NET"
    if host.startswith("app"): return "DC_APP"

    # IP-based
    if src_ip.startswith("10.0.1.") or dst_ip.startswith("10.0.1."):
        return "NET_SEGMENT_A"
    if src_ip.startswith("10.0.2.") or dst_ip.startswith("10.0.2."):
        return "NET_SEGMENT_B"
    if src_ip.startswith("172.16.") or dst_ip.startswith("172.16."):
        return "INTERNAL_DMZ"

    # Physical
    if "badge" in raw or door:
        return f"PHYS_{door.replace(' ', '_').upper() or 'ENTRY'}"
    if sensor:
        return f"ENV_{sensor.upper()}"

    # Fallback hashed host
    if host:
        return f"HOST_{hashlib.md5(host.encode()).hexdigest()[:6].upper()}"

    return "UNK"

# ---------- Categorizer ----------
def categorize(entry):
    text = (entry.get("raw") or "").lower()
    src = entry.get("source_file", "").lower()
    evt = entry.get("event_type", "").lower()

    # Base category
    category = CATEGORY_MAP.get(evt, CATEGORY_MAP.get(src.split('.')[0], "unknown"))

    # Base sub-category
    sub_category = "general"
    for k, v in KEYWORDS.items():
        if k in text:
            sub_category = v
            break

    # Base severity inference
    if any(w in text for w in ["error", "failed", "denied", "drop", "reject"]):
        severity = "high"
    elif any(w in text for w in ["warn", "delay", "timeout"]):
        severity = "medium"
    else:
        severity = "low"

    # ------ GROUND TRUTH ENHANCEMENTS ------
    gt = entry.get("ground_truth", 0)

    # Duplicate ML-friendly alias
    entry["gt"] = gt

    # Auto-upgrade severity for true threats
    if gt == 1:
        severity = "high"
        if sub_category == "general":
            sub_category = "threat"

    # Attach enriched properties
    entry["category"] = category
    entry["sub_category"] = sub_category
    entry["severity"] = severity
    entry["location_id"] = infer_location(entry)

    return entry

# ---------- Cleaning loop ----------
def clean_logs(input_file=INPUT_FILE, output_file=OUTPUT_FILE):
    total = 0
    with open(input_file, "r", encoding="utf-8") as infile, \
         open(output_file, "w", encoding="utf-8") as outfile:

        for line in tqdm(infile, desc="Categorizing logs"):
            try:
                entry = json.loads(line)

                # Ensure ground_truth field is numeric
                if "ground_truth" in entry:
                    entry["ground_truth"] = int(entry["ground_truth"])

                entry = categorize(entry)
                json.dump(entry, outfile)
                outfile.write("\n")
                total += 1

            except json.JSONDecodeError:
                continue

    print(f"\n✅ Cleaned {total:,} logs → {output_file}")

if __name__ == "__main__":
    clean_logs()
