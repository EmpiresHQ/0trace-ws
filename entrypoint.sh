#!/bin/sh

# Disable reverse path filtering (allows packets with "unusual" source IPs)
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0

exec node --experimental-strip-types server.ts
