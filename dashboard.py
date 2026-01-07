#!/usr/bin/env python3
import streamlit as st
import pandas as pd, numpy as np, json, os, subprocess
import plotly.express as px
from datetime import datetime

# ==============================================================
# PATHS
# ==============================================================
OUTPUT_DIR = "output"
FINAL_CSV = f"{OUTPUT_DIR}/final_data.csv"
METRICS_JSON = f"{OUTPUT_DIR}/metrics_report_full_ml.json"
SHAP_SCRIPT = "shap6.py"

# ==============================================================
# STREAMLIT CONFIG
# ==============================================================

st.set_page_config(
    layout="wide",
    page_title="Vanguard SOC Dashboard",
)

# Dark mode toggle
dark_mode = st.sidebar.checkbox("🌙 Dark Mode", value=True)

if dark_mode:
    st.markdown(
        """
        <style>
        body { background-color: #111 !important; color: #ddd !important; }
        .stApp { background-color: #111 !important; }
        .css-18e3th9 { color: #ddd !important; }
        .css-1d391kg { color: #ddd !important; }
        .css-10trblm { color: #ddd !important; }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ==============================================================
# LOAD DATA
# ==============================================================

@st.cache_data(ttl=60)
def load_data():
    # Final CSV
    if os.path.exists(FINAL_CSV):
        df = pd.read_csv(FINAL_CSV, low_memory=False)
    else:
        st.error("❌ final_data.csv not found. Run ML pipeline + final_data.py first.")
        return None, None

    # Metrics JSON
    if os.path.exists(METRICS_JSON):
        metrics = json.load(open(METRICS_JSON, "r"))
    else:
        metrics = {}

    # Normalize metrics format
    if "metrics" in metrics:
        metrics = metrics["metrics"]

    return df, metrics

df, metrics = load_data()
if df is None:
    st.stop()

# ==============================================================
# COLUMN AUTODETECTION
# ==============================================================

label_col = None
prob_col = None

for c in ["pred_label", "predicted_label"]:
    if c in df.columns:
        label_col = c
        break

for c in ["pred_prob", "predicted_prob"]:
    if c in df.columns:
        prob_col = c
        break

risk_col = "risk_score" if "risk_score" in df.columns else None

# ==============================================================
# TOP KPIs
# ==============================================================

st.title("🔰 Vanguard — SOC ML Dashboard")

k1, k2, k3, k4, k5 = st.columns(5)

k1.metric("Total Events", f"{len(df):,}")

if label_col:
    k2.metric("Model Alerts", f"{int(df[label_col].sum()):,}")
else:
    k2.metric("Model Alerts", "N/A")

# UEBA count based on final_data columns
if "uebaflag" in df.columns:
    ueba_count = int(df["uebaflag"].sum())
elif "isueba" in df.columns:
    ueba_count = int(df["isueba"].sum())
elif "ueba_flag" in df.columns:
    ueba_count = int(df["ueba_flag"].sum())
elif "is_ueba" in df.columns:
    ueba_count = int(df["is_ueba"].sum())
else:
    ueba_count = 0

k3.metric("UEBA Anomalies", f"{ueba_count:,}")

if risk_col:
    k4.metric("Avg Risk Score", f"{df[risk_col].mean():.2f}")
else:
    k4.metric("Avg Risk Score", "N/A")

sev = "severity" if "severity" in df.columns else None
if sev:
    k5.metric("Top Severity", df[sev].mode().iat[0])
else:
    k5.metric("Top Severity", "N/A")

# ==============================================================
# TIMELINE + RISK HISTOGRAM
# ==============================================================

left, right = st.columns([3, 2])

with left:
    st.subheader("📅 Event Timeline")
    df["date_only"] = pd.to_datetime(df["datetime"]).dt.date
    daily = df.groupby("date_only").size().reset_index(name="count")
    fig = px.line(daily, x="date_only", y="count", title="Events per Day")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("🔥 Top Source IPs (Alerts)")
    if label_col and "src_ip" in df.columns:
        src_alerts = df[df[label_col] == 1]["src_ip"].value_counts().head(20)
        st.dataframe(src_alerts)

with right:
    st.subheader("🎯 Risk Score Distribution")
    if risk_col:
        fig2 = px.histogram(df, x=risk_col, nbins=50, title="Risk Scores")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("Risk score not available.")

    st.subheader("⚠ High-Risk Events")
    if risk_col:
        cols = ["datetime", "src_ip", "host", label_col, prob_col, risk_col, "raw"]
        cols = [c for c in cols if c in df.columns]
        st.dataframe(df.sort_values(risk_col, ascending=False).head(10)[cols])

# ==============================================================
# UEBA HEATMAP
# ==============================================================

st.subheader("🔥 UEBA Heatmap")

if "ueba_flag" in df.columns and "hour_of_day" in df.columns and "day_of_week" in df.columns:
    heat = (
        df[df["ueba_flag"] == 1]
        .groupby(["day_of_week", "hour_of_day"])
        .size()
        .reset_index(name="count")
    )
    if not heat.empty:
        heat_pivot = heat.pivot(index="day_of_week",
                                columns="hour_of_day",
                                values="count").fillna(0)
        fig3 = px.imshow(heat_pivot, title="UEBA Activity Heatmap", aspect="auto")
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No UEBA anomalies to display.")
else:
    st.info("UEBA data missing")

# ==============================================================
# EVENT EXPLORER
# ==============================================================

st.subheader("🔎 Event Explorer")

with st.expander("Filters", expanded=True):
    col1, col2, col3 = st.columns(3)
    f_src = col1.text_input("Filter src_ip")
    f_host = col2.text_input("Filter host")
    f_min_risk = col3.slider("Minimum Risk", 0, 100, 10)

filtered = df.copy()

if f_src:
    filtered = filtered[filtered["src_ip"].astype(str).str.contains(f_src)]
if f_host:
    filtered = filtered[filtered["host"].astype(str).str.contains(f_host)]
if risk_col:
    filtered = filtered[filtered[risk_col] >= f_min_risk]

explore_cols = ["datetime", "src_ip", "host", "raw"]

if label_col:
    explore_cols.append(label_col)
if prob_col:
    explore_cols.append(prob_col)
if risk_col:
    explore_cols.append(risk_col)

explore_cols = [c for c in explore_cols if c in filtered.columns]

st.dataframe(filtered[explore_cols].sort_values("datetime", ascending=False).head(500))

# ==============================================================
# SHAP EXPLAINABILITY
# ==============================================================

st.subheader("🧠 SHAP Explainability")

ev_idx = st.number_input(
    "Event index", min_value=0, max_value=len(df) - 1, value=0, step=1
)

if st.button("Compute SHAP Explanation"):
    if not os.path.exists(SHAP_SCRIPT):
        st.error("❌ SHAP script not found.")
    else:
        cmd = ["python3", SHAP_SCRIPT, "--event-index", str(ev_idx)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            st.text(res.stdout)
            if res.stderr:
                st.text("ERROR:\n" + res.stderr)
        except Exception as e:
            st.error(str(e))

st.caption("💡 Tip: You can compute a full SHAP sample offline and load it here instead.")
