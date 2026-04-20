#!/bin/sh
nft add table inet r1_baseline
nft add chain inet r1_baseline r1_forwarding '{ type filter hook forward priority 0; policy drop; }'

# Always allow return traffic for existing flows
nft add rule inet r1_baseline r1_forwarding ct state established,related accept

# Workstations (10.1.0.0/24) may initiate to anywhere
nft add rule inet r1_baseline r1_forwarding ip saddr 10.1.0.0/24 ct state new accept

