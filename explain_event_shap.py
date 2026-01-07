#!/usr/bin/env python3
import os
import json
import argparse
import warnings
import logging
import time
from typing import Tuple, Dict, List, Optional
from dataclasses import dataclass
from functools import wraps

import numpy as np
import pandas as pd
import scipy.sparse as sp
import requests

from catboost import CatBoostClassifier

try:
    import shap
except ImportError:
    shap = None

# ------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("VANGUARD")
warnings.filterwarnings("ignore")

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
@dataclass
class Config:
    HF_API_TOKEN: str = os.getenv("HF_API_TOKEN", "")
    HF_MODEL: str = "HuggingFaceTB/SmolLM3-3B:hf-inference"
    HF_RATE_LIMIT: int = 300

    OUTPUT_DIR: str = "output"
    MODEL_PATH: str = "output/catboost_classifier.cbm"
    AUG_CSV: str = "output/features_augmented_full_ml.csv"
    HYBRID_X: str = "output/hybrid_features_sparse.npz"

    CRITICAL_THRESHOLD: float = 0.85
    HIGH_THRESHOLD: float = 0.60

    def validate(self):
        os.makedirs(self.OUTPUT_DIR, exist_ok=True)

        for f in (self.MODEL_PATH, self.AUG_CSV, self.HYBRID_X):
            if not os.path.exists(f):
                raise RuntimeError(f"Missing required file: {f}")

        # ✅ AUTO-SET TOKEN IF MISSING (PROCESS-LOCAL)
        if not self.HF_API_TOKEN:
            os.environ["HF_API_TOKEN"] = "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"
            self.HF_API_TOKEN = "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"

        return self

# ------------------------------------------------------------
# RATE LIMITER
# ------------------------------------------------------------
class RateLimiter:
    def __init__(self, max_requests_per_hour: int):
        self.max_requests = max_requests_per_hour
        self.timestamps: List[float] = []

    def allow(self) -> Tuple[bool, Optional[int]]:
        now = time.time()
        self.timestamps = [t for t in self.timestamps if t > now - 3600]
        if len(self.timestamps) >= self.max_requests:
            wait = int(3600 - (now - self.timestamps[0])) + 1
            return False, wait
        self.timestamps.append(now)
        return True, None

# ------------------------------------------------------------
# RETRY DECORATOR
# ------------------------------------------------------------
def with_exponential_backoff(max_retries=3, base_delay=1.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    logger.warning(f"Retry {attempt+1}/{max_retries} failed: {e}")
                    time.sleep(delay)
                    delay *= 2
        return wrapper
    return decorator

# ------------------------------------------------------------
# JSON SAFETY
# ------------------------------------------------------------
def to_json_safe(obj):
    if isinstance(obj, dict):
        return {k: to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_json_safe(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (bool, np.bool_)):
        return bool(obj)
    if isinstance(obj, pd.Timestamp):
        return obj.isoformat()
    try:
        if pd.isna(obj):
            return None
    except Exception:
        pass
    return obj

def safe_json_extract(text: str) -> Dict:
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
    except Exception:
        pass
    return {
        "attack_type": "PARSING_ERROR",
        "confidence": 0.0,
        "summary": "Failed to parse LLM response",
        "raw": text[:300]
    }

# ------------------------------------------------------------
# DETECTOR
# ------------------------------------------------------------
class VanguardDetector:
    def __init__(self, config: Config):
        self.cfg = config.validate()

        self.model = CatBoostClassifier()
        self.model.load_model(self.cfg.MODEL_PATH)

        self.X = sp.load_npz(self.cfg.HYBRID_X)
        self.df = pd.read_csv(self.cfg.AUG_CSV)
        self.feature_names = list(self.df.columns)

        self.rate_limiter = RateLimiter(self.cfg.HF_RATE_LIMIT)

        self.explainer = None
        if shap is not None:
            try:
                self.explainer = shap.TreeExplainer(self.model)
            except Exception as e:
                logger.warning(f"SHAP init failed: {e}")

    # --------------------------------------------------------
    # HF ROUTER CALL
    # --------------------------------------------------------
    @with_exponential_backoff()
    def call_ai(self, facts: Dict) -> Dict:
        headers = {
            "Authorization": f"Bearer {self.cfg.HF_API_TOKEN}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.cfg.HF_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a most technical senior SOC analyst. "
                        "Respond ONLY with valid JSON. "
                        "No markdown, no explanations outside JSON."
                    )
                },
                {
                    "role": "user",
                    "content": f"""
Schema:
{{
  "attack_type": "string",
  "confidence": 0.0,
  "summary": "2-4 sentence explanation",
  "recommended_actions": ["actions"],
  "mitre_techniques": ["technique used"],
  "false_positive_checks": ["checks"]
}}

Facts:
{json.dumps(to_json_safe(facts), indent=2)}
"""
                }
            ],
            "temperature": 0.2,
            "max_tokens": 400
        }

        allowed, wait = self.rate_limiter.allow()
        if not allowed:
            time.sleep(wait)

        resp = requests.post(
            "https://router.huggingface.co/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )

        if resp.status_code != 200:
            raise RuntimeError(
                f"HF Router error {resp.status_code}: {resp.text[:200]}"
            )

        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        return safe_json_extract(text)

    # --------------------------------------------------------
    # EVENT ANALYSIS
    # --------------------------------------------------------
    def analyze_event(self, index: int) -> Dict:
        row = self.df.iloc[index]
        x = self.X[index]

        proba = float(self.model.predict_proba(x)[0, 1])

        severity = (
            "CRITICAL" if proba >= self.cfg.CRITICAL_THRESHOLD else
            "HIGH" if proba >= self.cfg.HIGH_THRESHOLD else
            "LOW"
        )

        shap_top = None
        if self.explainer is not None:
            try:
                vals = self.explainer.shap_values(x)[1]
                shap_top = dict(
                    sorted(
                        zip(self.feature_names, vals.tolist()),
                        key=lambda i: abs(i[1]),
                        reverse=True
                    )[:10]
                )
            except Exception:
                pass

        facts = {
            "event_index": index,
            "severity": severity,
            "ml_probability": proba,
            "top_features": shap_top,
            "raw_features": row.to_dict()
        }

        ai = self.call_ai(facts)

        return {
            "severity": severity,
            "ml_probability": proba,
            "top_features": shap_top,
            "ai_analysis": ai
        }

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="VANGUARD UEBA Detector")
    parser.add_argument("--event-index", type=int, required=True)
    args = parser.parse_args()

    detector = VanguardDetector(Config())
    result = detector.analyze_event(args.event_index)

    print(json.dumps(to_json_safe(result), indent=2))

if __name__ == "__main__":
    main()
