#!/usr/bin/env python3
"""
clean_logs_for_ml_v2.py

Cleans, categorizes, and adds location_id to logs.
Produces an ML-ready dataset (cleaned_logs.jsonl).
"""

import json
import re
from tqdm import tqdm
import hashlib

INPUT_FILE = "merged_logs.jsonl"
OUTPUT_FILE = "cleaned_logs.jsonl"

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

KEYWORDS = {
    "login": "authentication", "password": "authentication", "sudo": "privilege",
    "role": "privilege", "failed": "failed_login", "accepted": "login_success",
    "error": "error", "warning": "warning", "query": "database_query",
    "transaction": "db_transaction", "blocked": "network_block", "drop": "network_block",
    "ids": "intrusion", "usb": "device_activity", "file": "file_access",
    "env": "sensor_alert", "badge": "physical_access"
}

# ---------- Location inference logic ----------
def infer_location(entry):
    """Assign logical or physical location_id based on clues."""
    raw = (entry.get("raw") or "").lower()
    host = (entry.get("host") or "").lower()
    src_ip = entry.get("src_ip", "")
    dst_ip = entry.get("dst_ip", "")
    project = entry.get("project", "")
    door = entry.get("door", "")
    sensor = entry.get("sensor", "")

    # 1. Cloud regions
    if "cloud" in entry.get("source_file", "").lower():
        if "us" in project: return "AWS_US_EAST"
        if "ap" in project: return "AWS_AP_SOUTH"
        if "eu" in project: return "AWS_EU_CENTRAL"
        return "CLOUD_GENERIC"

    # 2. Hostname mappings (web01, db01, proxy01)
    if host.startswith("web"): return "DC_WEB"
    if host.startswith("db"): return "DC_DB"
    if host.startswith("proxy"): return "DC_NET"
    if host.startswith("app"): return "DC_APP"

    # 3. IP subnet grouping
    if src_ip.startswith("10.0.1.") or dst_ip.startswith("10.0.1."):
        return "NET_SEGMENT_A"
    if src_ip.startswith("10.0.2.") or dst_ip.startswith("10.0.2."):
        return "NET_SEGMENT_B"
    if src_ip.startswith("172.16.") or dst_ip.startswith("172.16."):
        return "INTERNAL_DMZ"

    # 4. Badge or sensor logs
    if "badge" in raw or door:
        return f"PHYS_{door.replace(' ', '_').upper() or 'ENTRY'}"
    if sensor:
        return f"ENV_{sensor.upper()}"

    # 5. Default: hash hostname for consistent ID
    if host:
        return f"HOST_{hashlib.md5(host.encode()).hexdigest()[:6].upper()}"

    return "UNK"

def categorize(entry):
    text = (entry.get("raw") or "").lower()
    src = entry.get("source_file", "").lower()
    evt = entry.get("event_type", "").lower()

    category = CATEGORY_MAP.get(evt, CATEGORY_MAP.get(src.split('.')[0], "unknown"))
    sub_category = "general"
    for k, v in KEYWORDS.items():
        if k in text:
            sub_category = v
            break

    if any(w in text for w in ["error", "failed", "denied", "drop", "reject"]):
        severity = "high"
    elif any(w in text for w in ["warn", "delay", "timeout"]):
        severity = "medium"
    else:
        severity = "low"

    entry["category"] = category
    entry["sub_category"] = sub_category
    entry["severity"] = severity
    entry["location_id"] = infer_location(entry)
    return entry

def clean_logs(input_file=INPUT_FILE, output_file=OUTPUT_FILE):
    total = 0
    with open(input_file, "r", encoding="utf-8") as infile, \
         open(output_file, "w", encoding="utf-8") as outfile:
        for line in tqdm(infile, desc="Categorizing logs"):
            try:
                entry = json.loads(line)
                entry = categorize(entry)
                json.dump(entry, outfile)
                outfile.write("\n")
                total += 1
            except json.JSONDecodeError:
                continue
    print(f"\n✅ Cleaned {total:,} logs → {output_file}")

if __name__ == "__main__":
    clean_logs()
