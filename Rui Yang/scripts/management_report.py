"""Management (non-technical) Incident Report (Rui Yang FYP).

Same underlying detections as report.py's Threat Analysis Report, but reworded
for a non-technical reader: what happened, when, whether data appears to have
left the network, what was done, and what to take away from it.

Deliberately does NOT claim to identify specific stolen files/data - the
engine only ever looks at flow metadata (packet counts, sizes, ports, timing),
never payload content, so it cannot know WHAT left, only roughly HOW MUCH.
That distinction is kept explicit in the wording below rather than glossed
over.

Rewritten 2026-08-04 for plainer, more natural sentences - the first version
read stiffly ("event(s)", "address(es)") and still leaked a raw /100 score
into what was supposed to be a jargon-free report. See the .bak file next to
this one for the original wording.

Import-only (no page-level Streamlit calls).
"""
from collections import Counter


def _plural(n, word, plural_word=None):
    """Proper singular/plural, not the 'event(s)' shortcut."""
    if n == 1:
        return word
    return plural_word or (word + "s")


# ── Plain-English translation of each detection type ─────────
_LAYMAN_WHAT_HAPPENED = [
    (("Port Scan", "NULL Scan", "Xmas Scan"),
     "An outside address checked which of our services would respond. "
     "This usually means someone was scouting the network before a real "
     "attack, rather than an attack in itself."),
    (("DDoS", "DoS", "Flood"),
     "An outside address sent far more traffic than normal to one of our "
     "services, overwhelming it so that real users couldn't get through."),
    (("Brute Force",),
     "An outside address kept trying different passwords to log into one "
     "of our systems."),
    (("Suspicious Port", "Bot"),
     "A device on our network was communicating with an address linked to "
     "known attack tools. This usually means the device has already been "
     "compromised and is checking in with an attacker."),
    (("Telnet",),
     "One of our systems was reached using an old, unencrypted remote-"
     "access method, which means a password sent this way could be "
     "intercepted."),
    (("DNS Tunneling",),
     "Unusually large lookup requests went out disguised as ordinary web "
     "address lookups. This method can be used to move data out of the "
     "network without being noticed by basic filters."),
    (("Oversized", "Bandwidth"),
     "Traffic to or from one of our systems was well outside its normal "
     "size or volume."),
    (("ML Anomaly",),
     "Our system flagged behaviour that didn't match any known attack "
     "pattern, so it's been surfaced for someone to take a closer look."),
]

_LAYMAN_TAKEAWAY = [
    (("Port Scan", "NULL Scan", "Xmas Scan"),
     "Nothing suggests this went further than probing. We recommend "
     "blocking this address and keeping an eye out for any follow-up "
     "activity."),
    (("DDoS", "DoS", "Flood"),
     "The goal here was to disrupt the service, not steal data. We "
     "recommend adding rate limits on the affected service so this has "
     "less impact next time."),
    (("Brute Force",),
     "We recommend locking accounts after repeated failed logins and "
     "changing any passwords this attempt may have exposed."),
    (("Suspicious Port", "Bot"),
     "The device involved should be checked for compromise - this is the "
     "finding most likely to involve data actually leaving the network "
     "(see the estimate above)."),
    (("Telnet",),
     "We recommend retiring this unencrypted method in favour of a more "
     "secure, encrypted alternative."),
    (("DNS Tunneling",),
     "We recommend reviewing DNS traffic and limiting outbound lookups to "
     "trusted servers."),
    (("Oversized", "Bandwidth"),
     "We recommend confirming this device was authorised to send this "
     "much traffic, and capping bandwidth if the spike wasn't expected."),
    (("ML Anomaly",),
     "We recommend a manual review to confirm whether this was harmless "
     "or a new type of attack our system doesn't recognise yet."),
]

_DEFAULT_WHAT = ("Traffic from an outside address was flagged as suspicious "
                  "by our automated monitoring.")
_DEFAULT_TAKEAWAY = ("We recommend reviewing this address and keeping the "
                      "logs in case it needs to be looked into further.")


def _match(reason, table, default):
    for keys, text in table:
        if any(k in reason for k in keys):
            return text
    return default


def format_bytes(n):
    """Human-readable size, e.g. 842 -> '842 B', 15000 -> '14.6 KB'."""
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != 'B' else f"{int(n)} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ── Plain-English differentiation between same-category incidents ──
# The base "what happened" sentence is a fixed template per attack type, so
# nine DDoS incidents would otherwise read identically. These translate real
# per-flow data (duration, target port) into qualitative, jargon-free
# language instead - real differentiation without exposing raw technical
# figures (those belong in the Technical Report, not here).
_BUSINESS_SERVICE = {
    # Known malware/C2 ports (rules.py's check_suspicious_port list) - for a
    # "Suspicious Port"/"Bot" finding the port itself IS the reason it was
    # flagged, so it should never fall through to the generic default below.
    4444:  "a channel associated with known attack tools",
    1337:  "a channel associated with known attack tools",
    31337: "a channel associated with known attack tools",
    6666:  "a channel associated with known attack tools",
    6667:  "a channel associated with known attack tools",
    6668:  "a channel associated with known attack tools",
    8080:  "a non-standard web port sometimes used for bot/proxy traffic",
    22:   "a remote administration channel",
    23:   "an outdated remote-access channel",
    3389: "a remote desktop service",
    3306: "a database server",
    5432: "a database server",
    1433: "a database server",
    53:   "the DNS (name lookup) service",
    445:  "a file-sharing service",
    389:  "the directory/authentication service",
    88:   "the authentication service",
    80:   "a public-facing web service",
    443:  "a public-facing web service",
}


def _service_for_port(port):
    return _BUSINESS_SERVICE.get(port, "an internal network service")


def _duration_phrase(duration_seconds):
    secs = duration_seconds or 0
    if secs < 1:
        return "a very brief, intense burst"
    if secs < 10:
        return "a short burst lasting a few seconds"
    if secs < 60:
        return "activity that continued for under a minute"
    return "activity that continued for over a minute"


def _plain_severity(level):
    """Map the technical 5-tier level to a management-facing sentence."""
    return {
        "Critical": "This is considered a serious, high-priority incident.",
        "High":     "This is considered a significant threat.",
        "Medium":   "This is considered a moderate-risk event.",
        "Low":      "This is considered a low-risk probing attempt.",
        "Normal":   "This did not rise to the level of a real threat.",
    }.get(level, "This was flagged for review.")


def build_incident_cards(alerts_df, get_ip_location):
    """One plain-English card per attacking flow, newest evidence first."""
    cards = []
    for _, row in alerts_df.iterrows():
        reason = str(row.get("Reason", ""))
        ip     = row.get("Src IP", "—")
        loc    = get_ip_location(ip)
        origin = (
            f"{loc.get('city','an unknown city')}, {loc.get('country','an unknown country')}"
            if loc else "an internal / private network address"
        )

        data_back = row.get("Data Sent Back (bytes)", 0) or 0
        if data_back > 0:
            exposure = (
                f"An estimated {format_bytes(data_back)} of traffic was sent "
                f"back to this address during the session. We can't say "
                f"exactly what that traffic contained - this system tracks "
                f"how much data moved, not what was inside it, and most "
                f"traffic today is encrypted anyway."
            )
        else:
            exposure = (
                "No data appears to have been sent back to this address, "
                "which fits with an attempt that didn't get a response."
            )

        what = _match(reason, _LAYMAN_WHAT_HAPPENED, _DEFAULT_WHAT)
        # Real per-flow differentiation, in plain English (no raw numbers) -
        # so incidents of the SAME attack type don't all read identically.
        what += (
            f" This was {_duration_phrase(row.get('Duration (s)', 0))}, "
            f"aimed at {_service_for_port(row.get('Port', 0))}."
        )

        cards.append({
            "src":        ip,
            "origin":     origin,
            "start":      row.get("Start Time", "—"),
            "end":        row.get("End Time", "—"),
            "level":      row.get("Threat Level", "—"),
            "score":      row.get("Threat Score", "—"),
            "severity_sentence": _plain_severity(str(row.get("Threat Level", "")).split()[-1]
                                                  if row.get("Threat Level") else ""),
            "what":       what,
            "takeaway":   _match(reason, _LAYMAN_TAKEAWAY, _DEFAULT_TAKEAWAY),
            "exposure":   exposure,
            "prior":      row.get("Prior Hits", 0),
        })
    return cards


def build_overall_summary(alerts_df, overall_score, overall_level):
    """One short paragraph for the top of the management report."""
    if alerts_df.empty:
        return ("No suspicious activity was detected in this capture. No "
                "further action is required.")

    n_events    = len(alerts_df)
    n_sources   = alerts_df['Src IP'].nunique()
    first_time  = alerts_df['Start Time'].min() if 'Start Time' in alerts_df else "an unrecorded time"
    last_time   = alerts_df['End Time'].max() if 'End Time' in alerts_df else "an unrecorded time"
    total_back  = int(alerts_df.get('Data Sent Back (bytes)', 0).sum()) if 'Data Sent Back (bytes)' in alerts_df else 0

    event_word  = _plural(n_events, "suspicious event")
    source_word = _plural(n_sources, "external address", "different external addresses")
    rating_lead = "This was rated" if n_events == 1 else "The most serious of these was rated"

    data_line = (
        f"Across everything flagged, an estimated {format_bytes(total_back)} "
        f"of traffic was sent back toward the outside addresses involved."
        if total_back > 0 else
        "No traffic was seen being sent back toward the outside addresses "
        "involved, which fits with attempts that didn't succeed in getting "
        "anything out."
    )

    return (
        f"Between {first_time} and {last_time}, we detected {n_events} "
        f"{event_word} coming from {n_sources} {source_word}. "
        f"{rating_lead} \"{overall_level}.\" {data_line} "
        f"You'll find what happened and what we recommend for each one "
        f"below."
    )


def attack_type_counts_plain(alerts_df):
    """Counter of plain-English attack categories (for a summary checklist)."""
    reason_names = alerts_df['Reason']
    labels = []
    for r in reason_names:
        labels.append(_match(str(r), [
            (("Port Scan", "NULL Scan", "Xmas Scan"), "Network probing / reconnaissance"),
            (("DDoS", "DoS", "Flood"), "Service-flooding attack"),
            (("Brute Force",), "Password-guessing attempt"),
            (("Suspicious Port", "Bot"), "Possible compromised-device activity"),
            (("Telnet",), "Unencrypted remote-access usage"),
            (("DNS Tunneling",), "Possible data-smuggling via DNS"),
            (("Oversized", "Bandwidth"), "Abnormal traffic volume"),
            (("ML Anomaly",), "Unusual activity (flagged automatically)"),
        ], "Other suspicious traffic"))
    return Counter(labels)
