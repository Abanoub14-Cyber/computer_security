#!/usr/bin/env python3
"""
ICMP ping sweep attack.
Run from the Internet host (10.2.0.2) against the DMZ subnet.
Usage: python3 attack_ICMP.py <target_subnet>
Example: python3 attack_ICMP.py 10.12.0.0/24
"""

import sys
from scapy.all import IP, ICMP, sr1, conf

conf.verb = 0

def ping_sweep(subnet):
    from ipaddress import ip_network
    live_hosts = []
    targets = list(ip_network(subnet, strict=False).hosts())
    print(f"[*] Scanning {len(targets)} addresses in {subnet}...")

    for ip in targets:
        ip_str = str(ip)
        pkt = IP(dst=ip_str) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=0)
        if reply is not None and reply.haslayer(ICMP):
            # type 0 = echo-reply
            if reply[ICMP].type == 0:
                print(f"[+] {ip_str} is alive")
                live_hosts.append(ip_str)

    print(f"\n[*] Scan complete. {len(live_hosts)} live hosts found:")
    for h in live_hosts:
        print(f"    {h}")

if __name__ == "__main__":
    subnet = sys.argv[1] if len(sys.argv) > 1 else "10.12.0.0/24"
    ping_sweep(subnet)
