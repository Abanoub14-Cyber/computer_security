#!/bin/sh
nft add table inet dns_protect
nft add chain inet dns_protect dns_reflection '{ type filter hook forward priority -10; policy accept; }'

# Rate limit DNS responses coming FROM the DNS server to prevent reflection flooding
nft add rule inet dns_protect dns_reflection \
    ip protocol udp \
    udp sport 5353 \
    meter dns_meter \
    '{ ip daddr timeout 60s limit rate over 3/second burst 5 packets }' \
    drop
