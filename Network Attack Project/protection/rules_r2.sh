#!/bin/sh
nft add table inet r2_baseline
nft add chain inet r2_baseline r2_forwarding '{ type filter hook forward priority 0; policy drop; }'

# Return traffic
nft add rule inet r2_baseline r2_forwarding ct state established,related accept

# Workstations may initiate to anywhere 
nft add rule inet r2_baseline r2_forwarding ip saddr 10.1.0.0/24 ct state new accept

# Internet may initiate only toward DMZ
nft add rule inet r2_baseline r2_forwarding ip saddr 10.2.0.0/24 ip daddr 10.12.0.0/24 ct state new accept

# Workaround to allow connections from ws to DMZ (see readme)
nft add rule inet r2_baseline r2_forwarding ip saddr 10.12.0.0/24 ip daddr 10.1.0.0/24 accept

