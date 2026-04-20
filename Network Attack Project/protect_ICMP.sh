#!/bin/sh

nft add table inet icmp_protect
nft add chain inet icmp_protect rate_limit_icmp '{ type filter hook forward priority -10; policy accept; }'

# Drop ICMP echo-requests that exceed the rate limit
nft add rule inet icmp_protect rate_limit_icmp \
    ip protocol icmp icmp type echo-request \
    meter rate_meter \
    '{ ip saddr limit rate over 5/second burst 3 packets }' \
    drop

