#!/usr/bin/env python3
"""
soc_dashboard.py

Streamlit dashboard:
 - Loads augmented CSV with risk_score
 - Loads metrics JSON
 - Shows KPIs, alert timeline, top source IPs, UEBA heatmap, event table
 - Allows selecting an event and viewing SHAP explanation (calls explain_event_shap tool)
"""

import streamlit as st
import pandas as pd, numpy as np, json, os, subprocess
import plotly.express as px
from datetime import datetime

AUG_RISK_CSV = "output/features_timeaware_augmented_catboost_with_risk.csv"
METRICS_JSON = "output/metrics_report_retrain.json"
SHAP_SCRIPT = "explain_event_shap.py"

st.set_page_config(layout="wide", page_title="Vanguard SOC Dashboard")

@st.cache_data(ttl=60)
def load_data():
    if not os.path.exists(AUG_RISK_CSV):
        # fallback to non-risk CSV
        fallback = "output/features_timeaware_augmented_catboost.csv"
        if os.path.exists(fallback):
            df = pd.read_csv(fallback, low_memory=False)
        else:
            st.error("Augmented CSV not found. Run training pipeline.")
            return None, None
    else:
        df = pd.read_csv(AUG_RISK_CSV, low_memory=False)
    metrics = {}
    if os.path.exists(METRICS_JSON):
        metrics = json.load(open(METRICS_JSON,"r"))
        # metrics might be direct metrics dict or wrapper
        if "metrics" in metrics:
            metrics = metrics["metrics"]
    return df, metrics

df, metrics = load_data()
if df is None:
    st.stop()

# Top KPI row
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Events", f"{len(df):,}")
k2.metric("Alerts", f"{int(df['predicted_label'].sum()):,}")
k3.metric("UEBA anomalies", f"{int(df.get('ueba_flag', df.get('is_ueba',0)).sum()):,}")
k4.metric("Avg risk", f"{df['risk_score'].mean():.2f}" if "risk_score" in df.columns else "N/A")
k5.metric("Top severity", df["severity"].mode().iat[0] if "severity" in df.columns else "N/A")

# Left: timeline + risk histogram
left, right = st.columns([3,2])
with left:
    st.subheader("Alert timeline (events/day)")
    df["date_only"] = pd.to_datetime(df["datetime"]).dt.date
    daily = df.groupby("date_only").size().reset_index(name="count")
    fig = px.line(daily, x="date_only", y="count", title="Events per day")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top source IPs (by alerts)")
    src_counts = df[df["predicted_label"]==1]["src_ip"].value_counts().reset_index().rename(columns={"index":"src_ip","src_ip":"alerts"})
    st.dataframe(src_counts.head(20))

with right:
    st.subheader("Risk score distribution")
    if "risk_score" in df.columns:
        fig2 = px.histogram(df, x="risk_score", nbins=50, title="Risk score (0-100)")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("Run risk_score.py first to compute risk scores.")

    st.subheader("Top risk events")
    st.dataframe(df.sort_values("risk_score", ascending=False).head(10)[["datetime","src_ip","host","predicted_label","predicted_prob","risk_score","raw"]])

# UEBA heatmap (hour vs day)
st.subheader("UEBA anomalies heatmap (hour_of_day x day_of_week)")
if "ueba_flag" in df.columns and "hour_of_day" in df.columns and "day_of_week" in df.columns:
    heat = df[df["ueba_flag"]==1].groupby(["day_of_week","hour_of_day"]).size().reset_index(name="count")
    heat_pivot = heat.pivot(index="day_of_week", columns="hour_of_day", values="count").fillna(0)
    fig3 = px.imshow(heat_pivot, labels=dict(x="Hour", y="Day of Week", color="Anomaly Count"), aspect="auto")
    st.plotly_chart(fig3, use_container_width=True)
else:
    st.info("No UEBA fields (ueba_flag/hour_of_day/day_of_week) available.")

# Event table + filters
st.subheader("Event Explorer")
with st.expander("Filters", expanded=True):
    col1, col2, col3 = st.columns(3)
    src = col1.text_input("src_ip filter")
    host = col2.text_input("host filter")
    min_risk = col3.slider("Min risk score", 0, 100, 10)

filtered = df.copy()
if src:
    filtered = filtered[filtered["src_ip"].astype(str).str.contains(src)]
if host:
    filtered = filtered[filtered["host"].astype(str).str.contains(host)]
if "risk_score" in filtered.columns:
    filtered = filtered[filtered["risk_score"] >= min_risk]

st.dataframe(filtered[["datetime","src_ip","host","predicted_label","predicted_prob","risk_score","raw"]].sort_values("datetime", ascending=False).head(500))

# SHAP inspector
st.subheader("SHAP Explainability")
st.write("Select an event index from the augmented CSV to compute SHAP for that event.")
ev_idx = st.number_input("Event index", min_value=0, max_value=len(df)-1, value=0, step=1)
if st.button("Compute SHAP for event"):
    # call explain_event_shap.py as subprocess (simpler than importing)
    if not os.path.exists(SHAP_SCRIPT):
        st.error("explain_event_shap.py not found in working directory.")
    else:
        # run and capture output
        cmd = ["python3", SHAP_SCRIPT, "--event-index", str(ev_idx)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
            st.text(res.stdout)
            if res.stderr:
                st.text(res.stderr)
        except Exception as e:
            st.error("Error running SHAP script: " + str(e))

st.caption("Tip: compute SHAP offline for a sample and load precomputed shap parquet for faster interactive exploration.")
