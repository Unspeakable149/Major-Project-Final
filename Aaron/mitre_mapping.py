"""MITRE ATT&CK mapping layer for Hybrid IDS.

Maps traffic_profile strings produced by live_backend.py ->
    mitre_technique_id   (e.g. "T1046")
    mitre_sub_technique  (e.g. "T1498.001")
    mitre_technique_name (e.g. "Network Service Discovery")
    mitre_tactic         (e.g. "Discovery")
    mitre_tactic_id      (e.g. "TA0007")

Reference: https://attack.mitre.org/  (ATT&CK v14, Enterprise matrix)

Usage
-----
    from mitre_mapping import tag_mitre
    technique_id, sub_id, technique_name, tactic, tactic_id = tag_mitre("Port Scan / Reconnaissance")
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Master mapping table
# Keys are substrings matched (case-insensitive) against traffic_profile.
# The first matching entry wins, so order matters — put more specific
# patterns before broad ones.
# ---------------------------------------------------------------------------
_MITRE_TABLE: list[dict] = [
    # ── Initial Access ───────────────────────────────────────────────────
    {
        "patterns": ["sql inject", "sqli"],
        "technique_id": "T1190",
        "sub_technique_id": "",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
    },
    # ── Credential Access ────────────────────────────────────────────────
    {
        "patterns": ["brute-force probe", "brute force", "brute_force", "sustained syn"],
        "technique_id": "T1110",
        "sub_technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
    },
    {
        "patterns": ["credential stuff"],
        "technique_id": "T1110",
        "sub_technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
    },
    {
        "patterns": ["kerberoast"],
        "technique_id": "T1558",
        "sub_technique_id": "T1558.003",
        "technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
    },
    {
        "patterns": ["ssl strip", "arp spoof", "arp poison", "mitm", "man-in-the-middle"],
        "technique_id": "T1557",
        "sub_technique_id": "T1557.001",
        "technique_name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
    },
    # ── Discovery ────────────────────────────────────────────────────────
    {
        "patterns": ["slow port scan"],
        "technique_id": "T1046",
        "sub_technique_id": "",
        "technique_name": "Network Service Discovery (Slow Scan)",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
    },
    {
        "patterns": ["port scan", "reconnaissance", "reconn"],
        "technique_id": "T1046",
        "sub_technique_id": "",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
    },
    {
        "patterns": ["ldap recon", "ldap enum"],
        "technique_id": "T1087",
        "sub_technique_id": "T1087.002",
        "technique_name": "Account Discovery: Domain Account",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
    },
    {
        "patterns": ["ping", "icmp probe", "host discovery"],
        "technique_id": "T1018",
        "sub_technique_id": "",
        "technique_name": "Remote System Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
    },
    {
        "patterns": ["background telemetry"],
        "technique_id": "T1040",
        "sub_technique_id": "",
        "technique_name": "Network Sniffing",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
    },
    # ── Lateral Movement ─────────────────────────────────────────────────
    {
        "patterns": ["smb lateral", "smb spread", "lateral movement"],
        "technique_id": "T1021",
        "sub_technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
    },
    {
        "patterns": ["rdp lateral", "rdp spray"],
        "technique_id": "T1021",
        "sub_technique_id": "T1021.001",
        "technique_name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
    },
    # ── Command and Control ──────────────────────────────────────────────
    {
        "patterns": ["dns tunnel", "dns c2", "dns channel"],
        "technique_id": "T1071",
        "sub_technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
    },
    {
        "patterns": ["c2 beacon", "beacon", "c2 channel", "c&c", "command and control", "stealth"],
        "technique_id": "T1071",
        "sub_technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
    },
    {
        "patterns": ["known malicious", "threat intel"],
        "technique_id": "T1071",
        "sub_technique_id": "",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
    },
    # ── Exfiltration ─────────────────────────────────────────────────────
    {
        "patterns": ["ftp exfil", "ftp transfer"],
        "technique_id": "T1048",
        "sub_technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol: Unencrypted",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
    },
    {
        "patterns": ["data exfil", "exfiltrat"],
        "technique_id": "T1041",
        "sub_technique_id": "",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
    },
    {
        "patterns": ["large data transfer", "bandwidth spike"],
        "technique_id": "T1030",
        "sub_technique_id": "",
        "technique_name": "Data Transfer Size Limits",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
    },
    # ── Impact ────────────────────────────────────────────────────────────
    {
        "patterns": ["syn flood", "ddos syn", "ddos"],
        "technique_id": "T1498",
        "sub_technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flood",
        "tactic": "Impact",
        "tactic_id": "TA0040",
    },
    {
        "patterns": ["high-volume flood", "high volume flood", "http flood"],
        "technique_id": "T1498",
        "sub_technique_id": "",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "tactic_id": "TA0040",
    },
    {
        "patterns": ["icmp flood", "ping flood"],
        "technique_id": "T1498",
        "sub_technique_id": "T1498.002",
        "technique_name": "Network Denial of Service: Reflection Amplification",
        "tactic": "Impact",
        "tactic_id": "TA0040",
    },
    {
        "patterns": ["ransomware", "encrypt"],
        "technique_id": "T1486",
        "sub_technique_id": "",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "tactic_id": "TA0040",
    },
    # ── Reconnaissance (pre-ATT&CK / Recon tactic) ───────────────────────
    {
        "patterns": ["active scan", "vuln scan", "nmap"],
        "technique_id": "T1595",
        "sub_technique_id": "T1595.001",
        "technique_name": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
    },
    # ── Benign / unclassified ─────────────────────────────────────────────
    {
        "patterns": ["whitelist", "whitelisted"],
        "technique_id": "N/A",
        "sub_technique_id": "",
        "technique_name": "Whitelisted Source",
        "tactic": "None",
        "tactic_id": "",
    },
    {
        "patterns": ["standard web", "web browsing", "normal"],
        "technique_id": "N/A",
        "sub_technique_id": "",
        "technique_name": "Benign Traffic",
        "tactic": "None",
        "tactic_id": "",
    },
]

# Tactic -> display color (used by dashboard badges)
TACTIC_COLORS: dict[str, str] = {
    "Initial Access":        "#E74C3C",
    "Execution":             "#C0392B",
    "Persistence":           "#8E44AD",
    "Privilege Escalation":  "#9B59B6",
    "Defense Evasion":       "#7D3C98",
    "Credential Access":     "#D35400",
    "Discovery":             "#E67E22",
    "Lateral Movement":      "#F39C12",
    "Collection":            "#F1C40F",
    "Command and Control":   "#27AE60",
    "Exfiltration":          "#1ABC9C",
    "Impact":                "#E74C3C",
    "Reconnaissance":        "#2980B9",
    "Resource Development":  "#3498DB",
    "None":                  "#555577",
}


def tag_mitre(traffic_profile: str) -> tuple[str, str, str, str, str]:
    """Return (technique_id, sub_technique_id, technique_name, tactic, tactic_id)
    for the given traffic_profile string.

    Falls back to ("T1040", "", "Network Sniffing", "Discovery", "TA0007")
    when no pattern matches — conservative assumption for unknown traffic.
    """
    profile_lower = traffic_profile.lower() if traffic_profile else ""

    for entry in _MITRE_TABLE:
        if any(pat in profile_lower for pat in entry["patterns"]):
            return (
                entry["technique_id"],
                entry["sub_technique_id"],
                entry["technique_name"],
                entry["tactic"],
                entry["tactic_id"],
            )

    # Default: unclassified → flag as potential sniffing / passive recon
    return ("T1040", "", "Network Sniffing (Unclassified)", "Discovery", "TA0007")


def mitre_url(technique_id: str, sub_technique_id: str = "") -> str:
    """Return the MITRE ATT&CK URL for a technique or sub-technique."""
    base = "https://attack.mitre.org/techniques"
    if not technique_id or technique_id == "N/A":
        return "https://attack.mitre.org/"
    tid = technique_id.replace(".", "/")
    if sub_technique_id:
        sub = sub_technique_id.split(".")[-1]
        return f"{base}/{tid}/{sub}/"
    return f"{base}/{tid}/"


def tactic_color(tactic: str) -> str:
    """Return hex color for a given tactic name."""
    return TACTIC_COLORS.get(tactic, TACTIC_COLORS["None"])
