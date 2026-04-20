#!/bin/sh

nft add table inet icmp_protect
nft add chain inet icmp_protect rate_limit_chain \
    '{ type filter hook forward priority -10; policy accept; }'

nft add map inet icmp_protect ip_tracker_map \
    '{ type ipv4_addr : counter; size 65536; flags dynamic,timeout; timeout 60s; }'

# Drop ICMP echo-requests that exceed the rate limit
nft add rule inet icmp_protect rate_limit_chain \
    ip protocol icmp icmp type echo-request \
    meter rate_meter \
    '{ ip saddr timeout 60s limit rate over 5/second burst 3 packets }' \
    drop

