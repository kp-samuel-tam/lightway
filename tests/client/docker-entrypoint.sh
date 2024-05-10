#!/bin/sh

set -eu

echo "Configuring client container networking"

tunname=lightway
tun_local_ip=100.64.0.6
tun_peer_ip=100.64.0.5

echo ""
echo "====================================================================="
echo "Ping server"
echo "====================================================================="
ping -W 1 -c 3 server

echo ""
echo "====================================================================="
echo "Setup Client TUN device $tunname $tun_local_ip <-> $tun_peer_ip"
echo "====================================================================="

ip tuntap add mode tun dev "${tunname}"
ip link set dev "${tunname}" mtu 1350
ip link set dev "${tunname}" up
ip addr replace "${tun_local_ip}" peer "${tun_peer_ip}" dev "${tunname}"
ip route replace default via "${tun_local_ip}" dev "${tunname}"

server=$(dig +short server)
server_iface=$(ip -j route get "$server" | jq -r .[0].dev)
echo ""
echo "====================================================================="
echo "Adding static route to server $server via $server_iface"
echo "====================================================================="
ip route add "$server" dev "$server_iface"

echo ""
ip addr show
echo ""
ip route show

echo ""
echo "====================================================================="
echo "Ping server"
echo "====================================================================="
ping -W 1 -c 3 server

echo ""
echo "====================================================================="
echo "Start lightway-client: --tun-name=${tunname} --tun-local-ip=${tun_local_ip} --tun-peer-ip=${tun_peer_ip} $*"
echo "====================================================================="

exec ./lightway-client --tun-name="${tunname}" --tun-local-ip="${tun_local_ip}" --tun-peer-ip="${tun_peer_ip}" "$@"
