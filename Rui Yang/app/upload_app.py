import os

import pandas as pd
import streamlit as st
import plotly.express as px

# Shared PCAP/GeoIP engine (paths anchored to the Rui Yang folder inside the module)
from pcap_engine import BASE_DIR, analyse_pcap, get_ip_location

# ── Page Config ───────────────────────────────────────────────
st.set_page_config(
    page_title="Hybrid IDPS",
    page_icon="🛡️",
    layout="wide"
)

# ── UI ────────────────────────────────────────────────────────
st.title("🛡️ Hybrid Intrusion Detection & Prevention System")
st.caption("CMP3602 — Diploma in Cybersecurity & Digital Forensics | Temasek Polytechnic")

# Tabs
tab1, tab2 = st.tabs(["📁 PCAP Analysis", "🌍 Threat Map"])

with tab1:
    st.header("Upload PCAP File for Analysis")
    st.info("Supports .pcap, .pcapng and .cap formats")

    uploaded = st.file_uploader(
        "Choose a PCAP file",
        type=['pcap', 'pcapng', 'cap']
    )

    if uploaded:
        # Save temp file
        tmp_path = os.path.join(BASE_DIR, f"temp_{uploaded.name}")
        with open(tmp_path, 'wb') as f:
            f.write(uploaded.read())

        with st.spinner("Analysing PCAP file..."):
            df_results = analyse_pcap(tmp_path)

        os.remove(tmp_path)

        if df_results.empty:
            st.warning("No flows found in this PCAP file.")
        else:
            # Summary metrics
            severe   = len(df_results[df_results['Severity'] == '🔴 Severe'])
            moderate = len(df_results[df_results['Severity'].str.contains('Moderate')])
            safe     = len(df_results[df_results['Severity'] == '✅ Safe'])
            total    = len(df_results)

            st.subheader("📊 Analysis Summary")
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Flows",   total)
            col2.metric("🔴 Severe",     severe)
            col3.metric("🟡 Moderate",   moderate)
            col4.metric("✅ Safe",        safe)

            # Severity chart
            st.subheader("📈 Severity Distribution")
            severity_counts = df_results['Severity'].value_counts().reset_index()
            severity_counts.columns = ['Severity', 'Count']
            fig = px.bar(
                severity_counts,
                x='Severity', y='Count',
                color='Severity',
                color_discrete_map={
                    '🔴 Severe':   'red',
                    '🟠 Moderate': 'orange',
                    '🟡 Moderate': 'yellow',
                    '✅ Safe':     'green'
                }
            )
            st.plotly_chart(fig, use_container_width=True)

            # Detection source breakdown
            st.subheader("🔍 Detection Source")
            source_counts = df_results[
                df_results['Severity'] != '✅ Safe'
            ]['Source'].value_counts().reset_index()
            source_counts.columns = ['Source', 'Count']
            fig2 = px.pie(
                source_counts,
                values='Count',
                names='Source',
                title='What caught the attacks?'
            )
            st.plotly_chart(fig2, use_container_width=True)

            # Alert table
            st.subheader("🚨 Alert Details")
            alerts = df_results[df_results['Severity'] != '✅ Safe']
            if not alerts.empty:
                st.dataframe(alerts, use_container_width=True)
            else:
                st.success("No threats detected in this PCAP file.")

            # Full results
            with st.expander("📋 View All Flows"):
                st.dataframe(df_results, use_container_width=True)

            # Store for threat map tab
            st.session_state['results'] = df_results

with tab2:
    st.header("🌍 Global Threat Origin Map")

    if 'results' not in st.session_state:
        st.info("Upload and analyse a PCAP file first to see the threat map.")
    else:
        df_results = st.session_state['results']
        attacks    = df_results[df_results['Severity'] != '✅ Safe']

        if attacks.empty:
            st.success("No threats to map — all traffic appears normal.")
        else:
            st.info("Resolving IP locations... (private IPs will be skipped)")

            locations = []
            unique_ips = attacks['Src IP'].unique()

            progress = st.progress(0)
            for i, ip in enumerate(unique_ips):
                loc = get_ip_location(ip)
                if loc:
                    # Add severity info
                    ip_attacks = attacks[attacks['Src IP'] == ip]
                    worst = ip_attacks['Severity'].iloc[0]
                    loc['severity'] = worst
                    loc['attacks']  = len(ip_attacks)
                    locations.append(loc)
                progress.progress((i + 1) / len(unique_ips))

            progress.empty()

            if locations:
                df_map = pd.DataFrame(locations)

                # Plotly world map
                fig_map = px.scatter_geo(
                    df_map,
                    lat='lat',
                    lon='lon',
                    hover_name='ip',
                    hover_data={
                        'country':  True,
                        'city':     True,
                        'isp':      True,
                        'attacks':  True,
                        'lat':      False,
                        'lon':      False
                    },
                    color_discrete_sequence=['red'],
                    size='attacks',
                    size_max=30,
                    title='Attack Origins'
                )
                fig_map.update_layout(
                    geo=dict(
                        showframe=False,
                        showcoastlines=True,
                        projection_type='natural earth'
                    ),
                    height=500
                )
                st.plotly_chart(fig_map, use_container_width=True)

                # Location table
                st.subheader("📍 Attacker Details")
                st.dataframe(
                    df_map[['ip', 'country', 'city', 'isp', 'attacks']],
                    use_container_width=True
                )
            else:
                st.warning("All attacker IPs are private/local — no locations to map.")
                st.info("Try uploading a PCAP with public IP addresses for the map to work.")
