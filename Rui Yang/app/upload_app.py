import os

import pandas as pd
import streamlit as st
import plotly.express as px

# Shared PCAP/GeoIP engine (paths anchored to the Rui Yang folder inside the module)
from pcap_engine import BASE_DIR, analyse_pcap, get_ip_location

import sys
sys.path.insert(0, os.path.join(BASE_DIR, 'scripts'))
from report import (
    build_reasons, build_actions, attack_breakdown, top_attackers,
    per_attack_cards, rank_by_threat_score
)
from management_report import (
    build_overall_summary, build_incident_cards, attack_type_counts_plain
)
from docx_report import build_technical_docx, build_management_docx

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
        # Streamlit reruns this whole script on ANY widget interaction (e.g. the
        # report-view toggle below), not just on a new upload. Without this cache,
        # every click would re-run analyse_pcap() on the same file, and since it
        # calls offender_history.record() for every alert flow, repeat clicks
        # silently kept re-recording the same flows as new offences, inflating
        # "Prior Hits" in the persistent DB. Only (re-)analyse when the uploaded
        # file itself has actually changed.
        upload_key = (uploaded.name, uploaded.size)
        if st.session_state.get('pcap_upload_key') != upload_key:
            tmp_path = os.path.join(BASE_DIR, f"temp_{uploaded.name}")
            with open(tmp_path, 'wb') as f:
                f.write(uploaded.read())

            with st.spinner("Analysing PCAP file..."):
                df_results = analyse_pcap(tmp_path)

            os.remove(tmp_path)
            st.session_state['pcap_upload_key'] = upload_key
            st.session_state['pcap_df_results'] = df_results
        else:
            df_results = st.session_state['pcap_df_results']

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

            # ── Threat Analysis Report (Enhancement Idea 1 + management view) ──
            st.markdown("---")
            st.subheader("📄 Incident Report")

            alerts_all = df_results[df_results['Severity'] != '✅ Safe']

            if alerts_all.empty:
                st.success(
                    "No threats detected. Overall Threat Level: 🟢 Normal (0/100)."
                )
            else:
                # ── Report view toggle ───────────────────────────
                if 'report_view' not in st.session_state:
                    st.session_state['report_view'] = 'technical'

                bcol1, bcol2 = st.columns(2)
                if bcol1.button("🔧 Technical Report", use_container_width=True,
                                 type="primary" if st.session_state['report_view'] == 'technical' else "secondary"):
                    st.session_state['report_view'] = 'technical'
                    st.rerun()
                if bcol2.button("🧑‍💼 Management Report", use_container_width=True,
                                 type="primary" if st.session_state['report_view'] == 'management' else "secondary"):
                    st.session_state['report_view'] = 'management'
                    st.rerun()

                # Overall score = highest single-flow threat score in the capture
                overall_score = int(alerts_all['Threat Score'].max())
                overall_level = alerts_all.loc[
                    alerts_all['Threat Score'].idxmax(), 'Threat Level'
                ]

                if st.session_state['report_view'] == 'technical':
                    # Headline score card
                    sc1, sc2, sc3 = st.columns(3)
                    sc1.metric("Threat Score", f"{overall_score} / 100")
                    sc2.metric("Threat Level", overall_level)
                    sc3.metric("Suspicious Flows", len(alerts_all))

                    st.progress(overall_score / 100)

                    # Detected attack types (checklist)
                    st.markdown("#### ✅ Detected")
                    breakdown = attack_breakdown(alerts_all)
                    for atk, cnt in breakdown.most_common():
                        st.markdown(f"- **{atk}** — {cnt} flow(s)")

                    # Possible reasons (dynamic)
                    st.markdown("#### 🧠 Possible Reasons")
                    for r in build_reasons(alerts_all):
                        st.markdown(f"- {r}")

                    # Suggested actions (dynamic)
                    st.markdown("#### 🛠️ Suggested Actions")
                    for a in build_actions(alerts_all):
                        st.markdown(f"- {a}")

                    # Top attackers (GeoIP-enriched)
                    st.markdown("#### 🌍 Top Attacking Sources")
                    attackers = top_attackers(alerts_all, get_ip_location, limit=5)
                    st.dataframe(pd.DataFrame(attackers), use_container_width=True)

                    # ── Per-attack detail cards ───────────────────────
                    # Always show the first N cards (matching the Management
                    # view's behaviour) instead of an all-or-nothing cutoff -
                    # that previously meant 6+ alerts showed ZERO per-attack
                    # detail on screen, worse than the Management view right
                    # next to it, which always shows at least the top 5.
                    # "First N" now means highest Threat Score, not just
                    # whichever flow happened to appear earliest in the file.
                    PER_ATTACK_LIMIT = 5
                    st.markdown("#### 🗂️ Per-Attack Breakdown")
                    ranked_alerts = rank_by_threat_score(alerts_all)
                    for card in per_attack_cards(ranked_alerts.head(PER_ATTACK_LIMIT), get_ip_location):
                        with st.container(border=True):
                            top = st.columns([3, 1])
                            top[0].markdown(
                                f"**{card['reason_name']}**  \n"
                                f"`{card['src']}` → `{card['dst']}` : "
                                f"port {card['port']}"
                            )
                            top[1].metric("Score", card['score'])
                            st.markdown(f"**Level:** {card['level']}")
                            st.markdown(f"**Why:** {card['why']}")
                            st.markdown(f"**Action:** {card['action']}")
                            st.caption(f"🌍 Origin: {card['origin']}")
                    if len(alerts_all) > PER_ATTACK_LIMIT:
                        st.info(
                            f"{len(alerts_all) - PER_ATTACK_LIMIT} additional attack(s) "
                            "not shown here. Expand 'View All Flows' for the full list, "
                            "or download the Word report below for full detail."
                        )

                    st.download_button(
                        "📄 Download as Word (.docx)",
                        data=build_technical_docx(alerts_all, overall_score,
                                                   overall_level, get_ip_location),
                        file_name="threat_analysis_report.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True,
                    )

                else:
                    # ── Management Report (plain English) ───────
                    st.markdown("#### 📝 Summary")
                    st.info(build_overall_summary(alerts_all, overall_score, overall_level))

                    st.markdown("#### ✅ What Was Detected")
                    for label, cnt in attack_type_counts_plain(alerts_all).most_common():
                        st.markdown(f"- **{label}** — {cnt} event" if cnt == 1
                                     else f"- **{label}** — {cnt} events")

                    st.markdown("#### 🗂️ Incident Details")
                    MGMT_CARD_LIMIT = 5
                    ranked_alerts = rank_by_threat_score(alerts_all)
                    cards = build_incident_cards(ranked_alerts, get_ip_location)
                    shown, extra = cards[:MGMT_CARD_LIMIT], cards[MGMT_CARD_LIMIT:]
                    for card in shown:
                        with st.container(border=True):
                            top = st.columns([3, 1])
                            top[0].markdown(
                                f"**Source:** {card['origin']}  \n"
                                f"**When:** {card['start']} to {card['end']}"
                            )
                            top[1].metric("Rating", card['level'])
                            st.markdown(f"**What happened:** {card['what']}")
                            st.markdown(f"**Data exposure:** {card['exposure']}")
                            st.markdown(f"**Severity:** {card['severity_sentence']}")
                            st.markdown(f"**Recommended next step / lesson learnt:** {card['takeaway']}")
                            if card['prior']:
                                _prior_word = "prior incident" if card['prior'] == 1 else "prior incidents"
                                st.caption(f"⚠️ This source has {card['prior']} {_prior_word} on record.")
                    if extra:
                        _extra_word = "additional lower-priority event" if len(extra) == 1 else "additional lower-priority events"
                        st.info(f"{len(extra)} {_extra_word} not shown here "
                                 "— see the Technical Report for the full list.")

                    st.download_button(
                        "📄 Download as Word (.docx)",
                        data=build_management_docx(alerts_all, overall_score,
                                                     overall_level, get_ip_location),
                        file_name="management_incident_report.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        use_container_width=True,
                    )

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
