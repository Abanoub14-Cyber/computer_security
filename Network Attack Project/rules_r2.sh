#!/bin/sh
nft flush ruleset

nft add table inet filter
nft add chain inet filter forward '{ type filter hook forward priority 0; policy drop; }'

# Return traffic
nft add rule inet filter forward ct state established,related accept

# Workstations may initiate to anywhere 
nft add rule inet filter forward ip saddr 10.1.0.0/24 ct state new accept

# Internet may initiate only toward DMZ
nft add rule inet filter forward ip saddr 10.2.0.0/24 ip daddr 10.12.0.0/24 ct state new accept

