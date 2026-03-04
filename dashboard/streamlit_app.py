"""
HoneyMed - Layer 4: Streamlit Threat Intelligence Dashboard
=============================================================
Real-time visualization of:
  - Live attacks being caught by the honeypot
  - ML model classifications with confidence scores
  - Attacker IP geolocation and frequency
  - Attack type distribution
  - SHA-256 blockchain-ready hashes
  - System health metrics
"""

import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.loader import get_config, get_base_dir

# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="HoneyMed - Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

cfg = get_config()
DB_PATH = os.path.join(get_base_dir(), "data", "classified_events.db")

# Color scheme for attack labels
LABEL_COLORS = {
    "Benign": "#00e676",
    "DoS": "#ff1744",
    "PortScan": "#ff9100",
    "BruteForce": "#d500f9",
    "Reconnaissance": "#2979ff",
}


# ---------------------------------------------------------------------------
# Database Helpers
# ---------------------------------------------------------------------------
@st.cache_resource
def get_db_connection():
    """Get a cached database connection."""
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def query_df(sql: str, params: tuple = ()) -> pd.DataFrame:
    """Execute SQL and return as DataFrame."""
    conn = get_db_connection()
    if conn is None:
        return pd.DataFrame()
    try:
        return pd.read_sql_query(sql, conn, params=params)
    except Exception:
        return pd.DataFrame()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=60)
    st.title("HoneyMed")
    st.caption("IoMT Threat Intelligence")
    st.divider()

    # Auto-refresh
    refresh_rate = st.selectbox("Auto-refresh", [3, 5, 10, 30, 60], index=1)
    st.caption(f"Refreshing every {refresh_rate}s")

    st.divider()

    # Filters
    st.subheader("Filters")
    show_benign = st.checkbox("Show Benign", value=False)
    ip_filter = st.text_input("Filter by IP", placeholder="e.g., 192.168.1.")

    st.divider()
    st.caption(f"Database: {DB_PATH}")
    st.caption(f"Version: {cfg.get('VERSION', '1.0.0')}")


# ---------------------------------------------------------------------------
# Main Dashboard
# ---------------------------------------------------------------------------
st.title("🛡️ HoneyMed Threat Intelligence Dashboard")
st.caption("Real-time IoMT honeypot monitoring & ML-powered attack detection")

# ---- Top Metrics Row ----
col1, col2, col3, col4, col5 = st.columns(5)

total_df = query_df("SELECT COUNT(*) as c FROM classified_events")
attacks_df = query_df("SELECT COUNT(*) as c FROM classified_events WHERE is_attack = 1")
unique_ips_df = query_df("SELECT COUNT(DISTINCT attacker_ip) as c FROM classified_events WHERE attacker_ip != ''")
avg_conf_df = query_df("SELECT AVG(confidence) as c FROM classified_events WHERE is_attack = 1")
recent_df = query_df("SELECT COUNT(*) as c FROM classified_events WHERE id > (SELECT MAX(id) - 100 FROM classified_events) AND is_attack = 1")

total = total_df["c"].iloc[0] if len(total_df) > 0 else 0
attacks = attacks_df["c"].iloc[0] if len(attacks_df) > 0 else 0
unique_ips = unique_ips_df["c"].iloc[0] if len(unique_ips_df) > 0 else 0
avg_conf = avg_conf_df["c"].iloc[0] if len(avg_conf_df) > 0 and avg_conf_df["c"].iloc[0] else 0
recent_attacks = recent_df["c"].iloc[0] if len(recent_df) > 0 else 0

col1.metric("Total Events", f"{total:,}")
col2.metric("Attacks Detected", f"{attacks:,}", delta=f"{recent_attacks} recent")
col3.metric("Unique Attackers", f"{unique_ips:,}")
col4.metric("Avg Confidence", f"{avg_conf:.1%}")
col5.metric("Attack Rate", f"{(attacks/max(total,1))*100:.1f}%")

st.divider()

# ---- Charts Row ----
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("Attack Type Distribution")
    label_df = query_df("""
        SELECT label, COUNT(*) as count
        FROM classified_events
        GROUP BY label
        ORDER BY count DESC
    """)
    if len(label_df) > 0:
        if not show_benign:
            label_df = label_df[label_df["label"] != "Benign"]

        fig = px.pie(
            label_df, names="label", values="count",
            color="label",
            color_discrete_map=LABEL_COLORS,
            hole=0.4,
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e0e6ed",
            margin=dict(t=20, b=20, l=20, r=20),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data yet. Start the honeypot and pipeline to see results.")

with chart_col2:
    st.subheader("Attacks Over Time")
    timeline_df = query_df("""
        SELECT * FROM attack_summary
        ORDER BY id DESC LIMIT 50
    """)
    if len(timeline_df) > 0:
        timeline_df = timeline_df.iloc[::-1]  # Chronological
        fig = go.Figure()
        for col_name, color, label in [
            ("dos_count", "#ff1744", "DoS"),
            ("portscan_count", "#ff9100", "PortScan"),
            ("bruteforce_count", "#d500f9", "BruteForce"),
            ("recon_count", "#2979ff", "Recon"),
        ]:
            if col_name in timeline_df.columns:
                fig.add_trace(go.Scatter(
                    x=list(range(len(timeline_df))),
                    y=timeline_df[col_name],
                    mode="lines+markers",
                    name=label,
                    line=dict(color=color),
                    marker=dict(size=4),
                ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e0e6ed",
            xaxis_title="Processing Window",
            yaxis_title="Count",
            margin=dict(t=20, b=40, l=40, r=20),
            legend=dict(orientation="h", yanchor="bottom", y=-0.3),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No timeline data yet.")

st.divider()

# ---- Second Charts Row ----
chart_col3, chart_col4 = st.columns(2)

with chart_col3:
    st.subheader("Top Attacker IPs")
    top_ip_df = query_df("""
        SELECT attacker_ip, COUNT(*) as count,
               SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) as attacks
        FROM classified_events
        WHERE attacker_ip != ''
        GROUP BY attacker_ip
        ORDER BY count DESC
        LIMIT 10
    """)
    if len(top_ip_df) > 0:
        fig = px.bar(
            top_ip_df, x="count", y="attacker_ip",
            color="attacks",
            orientation="h",
            color_continuous_scale="Reds",
            labels={"count": "Total Events", "attacks": "Attacks"},
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e0e6ed",
            margin=dict(t=20, b=20, l=20, r=20),
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig, use_container_width=True)

with chart_col4:
    st.subheader("Targeted Services")
    service_df = query_df("""
        SELECT service, COUNT(*) as count
        FROM classified_events
        WHERE service != ''
        GROUP BY service
    """)
    if len(service_df) > 0:
        fig = px.bar(
            service_df, x="service", y="count",
            color="service",
            color_discrete_sequence=px.colors.qualitative.Set2,
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e0e6ed",
            margin=dict(t=20, b=20, l=20, r=20),
            showlegend=False,
        )
        st.plotly_chart(fig, use_container_width=True)

st.divider()

# ---- Live Event Feed ----
st.subheader("📡 Live Event Feed")

where_clauses = []
params = []
if not show_benign:
    where_clauses.append("is_attack = 1")
if ip_filter:
    where_clauses.append("attacker_ip LIKE ?")
    params.append(f"%{ip_filter}%")

where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

events_df = query_df(f"""
    SELECT id, timestamp, attacker_ip, attacker_port, service, event_type,
           label, confidence, sha256_hash
    FROM classified_events
    {where_sql}
    ORDER BY id DESC LIMIT 30
""", tuple(params))

if len(events_df) > 0:
    # Color-code the labels
    def color_label(val):
        color = LABEL_COLORS.get(val, "#ffffff")
        return f"color: {color}; font-weight: bold"

    styled = events_df.style.map(color_label, subset=["label"])
    st.dataframe(styled, use_container_width=True, height=400)
else:
    st.info("No events to display. Start the honeypot and run some attacks!")

st.divider()

# ---- Blockchain Readiness Section ----
st.subheader("🔗 Blockchain-Ready Hashes")
st.caption("SHA-256 hashes generated for each event — ready for Hyperledger Fabric ledger submission")

hash_df = query_df("""
    SELECT id, timestamp, attacker_ip, label, sha256_hash
    FROM classified_events
    WHERE sha256_hash != ''
    ORDER BY id DESC LIMIT 15
""")

if len(hash_df) > 0:
    for _, row in hash_df.iterrows():
        label_color = LABEL_COLORS.get(row["label"], "#ffffff")
        st.markdown(
            f"**#{row['id']}** | "
            f"`{row['sha256_hash'][:32]}...` | "
            f"<span style='color:{label_color}'>{row['label']}</span> | "
            f"{row['attacker_ip']} | {row['timestamp']}",
            unsafe_allow_html=True,
        )

st.divider()

# ---- Auto-refresh ----
time.sleep(refresh_rate)
st.rerun()
