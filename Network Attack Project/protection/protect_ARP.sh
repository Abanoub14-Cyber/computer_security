#!/bin/sh
# protect_ARP.sh — receives MACs as arguments
# Usage: protect_ARP.sh <r1_mac> <ws3_mac>

INTERFACE="ws2-eth0"
R1_MAC="$1"
WS3_MAC="$2"

if [ -z "$R1_MAC" ] || [ -z "$WS3_MAC" ]; then
    echo "[!] Usage: protect_ARP.sh <r1_mac> <ws3_mac>"
    exit 1
fi

echo "[*] Installing static ARP entries on $INTERFACE"
ip neigh flush dev "$INTERFACE"

ip neigh replace 10.1.0.1 lladdr "$R1_MAC" dev "$INTERFACE" nud permanent
echo "[+] Pinned 10.1.0.1 -> $R1_MAC (PERMANENT)"

ip neigh replace 10.1.0.3 lladdr "$WS3_MAC" dev "$INTERFACE" nud permanent
echo "[+] Pinned 10.1.0.3 -> $WS3_MAC (PERMANENT)"

echo ""
echo "[*] Final ARP cache state:"
ip neigh show dev "$INTERFACE"
