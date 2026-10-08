#!/bin/sh
# Runs inside the node's network namespace and plays an on-path censor.
# Silent drops match the replies (INPUT): dropping our own packets on OUTPUT
# would surface as local EPERM errors, which a real middlebox never causes.
set -eu
T=172.30.0.20

iptables -A OUTPUT -d $T -p tcp --dport 7001 -j REJECT --reject-with tcp-reset
iptables -A INPUT  -s $T -p tcp --sport 7002 -j DROP
iptables -A OUTPUT -d $T -p tcp --dport 9443 -m string --string "blocked-sni.test" --algo bm -j REJECT --reject-with tcp-reset
iptables -A OUTPUT -d $T -p tcp --dport 8080 -m string --string "forbidden-keyword" --algo bm -j REJECT --reject-with tcp-reset
iptables -A INPUT  -s $T -p udp --sport 8443 -j DROP
iptables -A INPUT  -s $T -p tcp --sport 8083 -m connbytes --connbytes 65536: --connbytes-dir reply --connbytes-mode bytes -j DROP

tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev eth0 parent ffff: protocol ip u32 \
    match ip src $T/32 match ip sport 8081 0xffff \
    police rate 1mbit burst 64k drop flowid :1

iptables -S
touch /tmp/ready
exec sleep infinity
