"""One-off test PCAP: DDoS flood against port 443 (HTTPS), for verifying the
WEB_PORTS fix in scripts/rules.py. generate_pcap.py's built-in ddos attack
always targets port 80, so this covers the 443 case separately.
"""
from scapy.all import IP, TCP, Raw, wrpcap
import time

pkts = []
t = time.time()
for i in range(500):
    p = IP(src="203.0.113.5", dst="192.168.1.100") / TCP(
        sport=40000 + i % 1000, dport=443, flags="PA"
    ) / Raw(load=b"X" * 800)
    p.time = t + i * 0.0005
    pkts.append(p)

wrpcap("test_443ddos.pcap", pkts)
print("Wrote test_443ddos.pcap (500 pkts, DDoS flood -> port 443)")
