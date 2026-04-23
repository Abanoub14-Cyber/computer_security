#!/bin/sh

nft add table inet SSH_protect

nft add chain inet SSH_protect SSH_blacklist '{ type filter hook forward priority -10; policy accept; }'
nft add set inet SSH_protect ssh_blacklist '{ type ipv4_addr; flags dynamic, timeout; timeout 5m; }'

nft add rule inet SSH_protect SSH_blacklist \
    ip saddr @ssh_blacklist \
    tcp dport 22 \
    drop

nft add rule inet SSH_protect SSH_blacklist \
    tcp dport 22 \
    ct state new \
    meter ssh_ratemeter { ip saddr limit rate over 3/minute } \
    add @ssh_blacklist '{ ip saddr }' drop
