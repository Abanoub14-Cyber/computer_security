#!/bin/sh
nft add table inet tcp_protect

nft add chain inet tcp_protect rate_limit_tcp '{ type filter hook forward priority -10; policy accept; }'
    
nft add rule inet tcp_protect rate_limit_tcp \
    ip protocol tcp \
    ct state new \
    meter tcp_scan '{ ip saddr limit rate over 5/second burst 3 packets }' \
    drop
