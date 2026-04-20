#!/usr/bin/env python3
"""
TCP SYN port scan.
Run from the Internet host (10.2.0.2) against a DMZ server.
Usage: python3 attack_TCP.py <target_ip> [start_port] [end_port]
Example: python3 attack_TCP.py 10.12.0.10 1 1024
"""

import sys
from scapy.all import IP, TCP, sr1, conf, send
from random import randint

conf.verb = 0

def syn_scan(target, start_port, end_port):
    open_ports = []

    print(f"[*] Scanning {target} ports {start_port}-{end_port}...")

    for port in range(start_port, end_port + 1):
        src_port = randint(1024, 65535)
        pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
        reply = sr1(pkt, timeout=0.1, verbose=0)
        if reply is not None and reply.haslayer(TCP):
            flags = reply[TCP].flags
            if flags == 0x12:  # SYN+ACK → port open
                print(f"[+] Port {port}/tcp OPEN")
                open_ports.append(port)
                rst = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R")
                send(rst, verbose=0)

    print(f"\n[*] Scan complete.")
    print(f"    Open:     {len(open_ports)} ports: {open_ports}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "10.12.0.10"
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    syn_scan(target, start, end)
