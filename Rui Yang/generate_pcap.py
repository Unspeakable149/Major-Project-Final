"""Synthetic attack-PCAP generator (Rui Yang FYP).

Builds a .pcap of attack traffic for testing the Hybrid IDPS upload feature.
Each run randomises BOTH the attack mix and the attacker source IPs, so you get
a different-but-valid test file every time. The crafted flows are tuned to the
thresholds in scripts/rules.py so each attack reliably fires its rule.

Usage:
    python generate_pcap.py                      # random mix, auto filename
    python generate_pcap.py my_test.pcap         # random mix, chosen filename
    python generate_pcap.py my_test.pcap 4        # force exactly 4 attacks

The victim is a fixed internal host (192.168.1.100). Attackers are random PUBLIC
IPs (so the GeoIP threat map + report resolve to real countries). A benign HTTPS
flow is always added so the capture isn't 100% malicious.
"""
import os
import random
import sys
import time

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

VICTIM = "192.168.1.100"

# ── Random public-IP helper ──────────────────────────────────
# Avoid private / reserved ranges so ip-api.com resolves them on the live app.
_PRIVATE_FIRST_OCTETS = {10, 127, 0, 169, 172, 192, 100, 198, 203}  # rough skip set


def random_public_ip():
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192, 0):
            continue
        b, c, d = (random.randint(0, 255), random.randint(0, 255),
                   random.randint(1, 254))
        return f"{a}.{b}.{c}.{d}"


def _base(src, dport, sport=None, flags="S", payload=b"", ttl=64):
    """One crafted packet from attacker->victim."""
    sport = sport or random.randint(1024, 65535)
    pkt = IP(src=src, dst=VICTIM, ttl=ttl) / TCP(
        sport=sport, dport=dport, flags=flags
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


# ── Attack builders — each returns (list_of_packets, label) ──
# Timings are set so Flow Duration / Packets-per-second land in the rule's window.

def atk_ddos(src):
    """Large packets flooding port 80 -> Rule 2 (DDoS)."""
    pkts, t = [], time.time()
    for i in range(500):
        p = _base(src, 80, flags="PA", payload=b"X" * 800)  # >500 byte mean
        p.time = t + i * 0.0005                              # ~2000 pkt/s
        pkts.append(p)
    return pkts, "DDoS"


def atk_port_scan(src):
    """One tiny SYN to each of 500 ports -> Rule 1 (Port Scan)."""
    pkts, t = [], time.time()
    for i, port in enumerate(range(1, 501)):
        p = _base(src, port, flags="S")                     # tiny, ~40 bytes
        p.time = t + i * 0.0002                              # very high pkt/s
        pkts.append(p)
    return pkts, "Port Scan"


def atk_brute_force(src):
    """Repeated small connects to port 22 -> Rule 4 (Brute Force)."""
    pkts, t = [], time.time()
    for i in range(400):
        p = _base(src, 22, flags="PA", payload=b"user:pass\r\n")  # <80 byte mean
        p.time = t + i * 0.2                                       # sustained, >50000us dur
        pkts.append(p)
    return pkts, "Brute Force"


def atk_bot(src):
    """Traffic to port 8080 above 20 pkt/s -> Rule 5 (Bot Activity)."""
    pkts, t = [], time.time()
    for i in range(300):
        p = _base(src, 8080, flags="PA", payload=b"BEACON")
        p.time = t + i * 0.02                                # ~50 pkt/s
        pkts.append(p)
    return pkts, "Bot Activity"


def atk_null_scan(src):
    """TCP packets with NO flags -> Rule 7 (NULL Scan)."""
    pkts, t = [], time.time()
    for i in range(300):
        p = _base(src, random.randint(1, 1024), flags="")   # no flags
        p.time = t + i * 0.002                               # >100 pkt/s
        pkts.append(p)
    return pkts, "NULL Scan"


# Base64-ish alphabet: what a tool encoding stolen bytes into a subdomain label
# actually emits. A label drawn from this lands around 4.3-4.5 bits/char, well
# clear of the 3.5 floor; ordinary hostnames sit near 2.7.
_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def atk_dns_tunnel(src):
    """High-entropy DNS query names -> Rule 11 (DNS Tunneling).

    Rule 11 used to be "any UDP/53 packet with a >200-byte mean", so this
    generator fired it with a raw 250-byte 'Q' payload and no DNS layer at all.
    The rule now parses the packet as DNS and measures Shannon entropy of the
    query's SUBDOMAIN labels, so that payload no longer triggers anything: it
    has no DNS layer, so 'Is DNS Flow' is 0 and the rule short-circuits.

    Real DNS queries carrying base64-style encoded subdomains are emitted
    instead, which is what the rule is now actually looking for.
    """
    pkts, t = [], time.time()
    for i in range(200):
        sport = random.randint(1024, 65535)
        label = "".join(random.choice(_B64_ALPHABET) for _ in range(32))
        qname = f"{label}.exfil.example.com"
        p = (IP(src=src, dst=VICTIM) /
             UDP(sport=sport, dport=53) /
             DNS(rd=1, qr=0, qd=DNSQR(qname=qname)))
        p.time = t + i * 0.01
        pkts.append(p)
    return pkts, "DNS Tunneling"


def atk_suspicious_port(src):
    """Traffic to a known malware port -> Rule 10 (Suspicious Port)."""
    port = random.choice([4444, 1337, 31337, 6666, 6667])
    pkts, t = [], time.time()
    for i in range(200):
        p = _base(src, port, flags="PA", payload=b"C2")
        p.time = t + i * 0.01
        pkts.append(p)
    return pkts, f"Suspicious Port {port}"


def atk_data_breach(src):
    """C2 check-in on a malware port, then a large VICTIM->attacker transfer.

    Simulates the "management report" scenario: a compromised host beacons
    out to an attacker-controlled address (fires Rule 10 - Suspicious Port),
    then sends a burst of large packets BACK to that address, standing in
    for stolen data leaving the network. Real payload content is never
    inspected by the engine (nor could it be over TLS) - this only exercises
    the byte-volume ("Data Sent Back") estimate used in the management report.
    """
    port = random.choice([4444, 1337, 31337, 6666, 6667])
    pkts, t = [], time.time()

    # Attacker -> victim: short C2 beacon traffic (fires Suspicious Port rule)
    for i in range(60):
        p = _base(src, port, flags="PA", payload=b"C2")
        p.time = t + i * 0.05
        pkts.append(p)

    # Victim -> attacker: large burst = data leaving the network
    exfil_start = t + 60 * 0.05
    for i in range(150):
        p = (IP(src=VICTIM, dst=src) /
             TCP(sport=port, dport=random.randint(1024, 65535), flags="PA") /
             Raw(load=b"D" * 1400))
        p.time = exfil_start + i * 0.02
        pkts.append(p)

    return pkts, f"Suspicious Port {port} (C2 + Data Exfiltration)"


def benign_https(src):
    """Normal-looking HTTPS flow so the capture isn't all attacks."""
    pkts, t = [], time.time()
    for i in range(300):
        p = _base(src, 443, flags="PA", payload=b"~" * random.randint(200, 600))
        p.time = t + i * 0.05
        pkts.append(p)
    return pkts, "Benign HTTPS"


ATTACKS = [
    atk_ddos, atk_port_scan, atk_brute_force, atk_bot,
    atk_null_scan, atk_dns_tunnel, atk_suspicious_port,
]

# Named registry so a specific attack can be requested from the command line,
# e.g.  python generate_pcap.py out.pcap ddos
#       python generate_pcap.py out.pcap ddos,bruteforce,bot
ATTACK_BY_NAME = {
    "ddos":           atk_ddos,
    "portscan":       atk_port_scan,
    "bruteforce":     atk_brute_force,
    "bot":            atk_bot,
    "nullscan":       atk_null_scan,
    "dnstunnel":      atk_dns_tunnel,
    "suspiciousport": atk_suspicious_port,
    "databreach":     atk_data_breach,
}


def generate(out_path, num_attacks=None, chosen=None):
    # `chosen` (an explicit list of attack builders) wins if provided;
    # otherwise pick a random subset.
    if chosen is None:
        if num_attacks is None:
            num_attacks = random.randint(3, len(ATTACKS))
        num_attacks = max(1, min(num_attacks, len(ATTACKS)))
        chosen = random.sample(ATTACKS, num_attacks)
    num_attacks = len(chosen)

    all_pkts = []
    summary = []
    base_t = time.time()
    for idx, builder in enumerate(chosen):
        src = random_public_ip()
        pkts, label = builder(src)
        # Offset each flow's start so they interleave across the capture
        # timeline instead of all beginning at the same instant.
        offset = idx * 0.7
        for p in pkts:
            p.time = float(p.time) + offset
        all_pkts.extend(pkts)
        summary.append((src, label, len(pkts)))

    # Always add one benign flow from another random public IP
    bsrc = random_public_ip()
    bpkts, blabel = benign_https(bsrc)
    for p in bpkts:
        p.time = float(p.time) + len(chosen) * 0.7
    all_pkts.extend(bpkts)
    summary.append((bsrc, blabel, len(bpkts)))

    # Sort by timestamp so the capture is chronologically ordered like a real
    # PCAP. (Shuffling would scramble per-flow first/last times and produce a
    # negative Flow Duration, which zeroes out packets-per-second.)
    all_pkts.sort(key=lambda p: float(p.time))
    wrpcap(out_path, all_pkts)

    print(f"Wrote {len(all_pkts)} packets to {out_path}")
    print(f"{num_attacks} attack flow(s) + 1 benign flow:")
    for src, label, n in summary:
        print(f"  {src:<16} {label:<22} {n} pkts")
    return out_path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else \
        f"generated_attack_{int(time.time())}.pcap"

    # Second arg is optional. It can be either:
    #   a number  -> that many RANDOM attacks   (e.g. 4)
    #   name(s)    -> those specific attacks     (e.g. ddos  or  ddos,bot,portscan)
    n, chosen = None, None
    if len(sys.argv) > 2:
        arg = sys.argv[2].strip().lower()
        if arg.isdigit():
            n = int(arg)
        else:
            names = [x.strip() for x in arg.replace(" ", "").split(",") if x.strip()]
            chosen = []
            for name in names:
                if name in ATTACK_BY_NAME:
                    chosen.append(ATTACK_BY_NAME[name])
                else:
                    print(f"Unknown attack '{name}'. "
                          f"Choose from: {', '.join(ATTACK_BY_NAME)}")
                    sys.exit(1)

    generate(out, num_attacks=n, chosen=chosen)