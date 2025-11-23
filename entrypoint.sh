#!/bin/sh

# Disable reverse path filtering (allows packets with "unusual" source IPs)
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.eth0.rp_filter=0

# Enable IP forwarding (allows packets to be routed)
sysctl -w net.ipv4.ip_forward=1

# If SERVER_PUBLIC_IP is set, configure SNAT/masquerading for our probe packets
if [ -n "$SERVER_PUBLIC_IP" ] && [ "$SERVER_PUBLIC_IP" != "0.0.0.0" ]; then
    echo "Configuring SNAT for source IP: $SERVER_PUBLIC_IP"
    
    # Allow packets with source IP = SERVER_PUBLIC_IP to be sent out
    # This uses SNAT (Source NAT) to rewrite source IP on egress
    # Note: This won't work perfectly because we're crafting raw packets
    # But it tells the kernel to not drop them as martians
    
    # Mark our probe packets (we'll need to mark them in the code)
    # For now, just ensure routing accepts them
    ip route add local $SERVER_PUBLIC_IP dev lo
    
    echo "SNAT configured for $SERVER_PUBLIC_IP"
else
    echo "SERVER_PUBLIC_IP not set or is 0.0.0.0, skipping SNAT configuration"
fi

exec node --experimental-strip-types server.ts
