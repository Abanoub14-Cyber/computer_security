#!/bin/sh

nft add rule inet filter forward \
    ip saddr 10.2.0.0/24 \
    icmp type echo-request \
    meter ping_flood { ip saddr limit rate over 5/second burst 10 packets } \
    drop
