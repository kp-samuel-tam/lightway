#!/bin/bash

set -euo pipefail

echo ""
echo "====================================================================="
echo "INITIAL ping TEST"
echo "====================================================================="

docker compose exec client ping -W 1 -c 3 nginx

# ---------------------------------------------------------------------

iface="eth0"
iface_info=$(docker compose exec client ip -j addr show "$iface")

current_ip=$(<<<"$iface_info" jq -r '.[0].addr_info[0].local')
prefix=$(<<<"$iface_info" jq -r '.[0].addr_info[0].prefixlen')

if [ "$prefix" -ne 24 ] ; then
    echo "Test has only been tested with /24 networking"
    exit 1
fi

current_network="${current_ip%.*}" # everything before third/final .
current_host="${current_ip##*.}" # everything after third/final .

# Result should be in the range 5..=250, we want to avoid 255
# (broadcast for a /24), 0 (network for a /24) and lower numbers where
# it's more likely other containers may have end up.
new_host=$(( ( current_host + 1 % 245 ) + 5 ))

new_ip="$current_network.$new_host"

echo ""
echo "====================================================================="
echo "FLOAT client IP ADDRESS: $current_ip/$prefix -> $new_ip/$prefix"
echo "====================================================================="

docker compose exec client ip addr show
echo ""
docker compose exec client ip route show

echo ""
echo "Switch $iface address from $current_ip/$prefix to $new_ip/$prefix"
docker compose exec client ip addr add dev "$iface" "$new_ip/$prefix"
docker compose exec client ip addr del dev "$iface" "$current_ip/$prefix"

echo ""
docker compose exec client ip addr show
echo ""
docker compose exec client ip route show

sleep 1s

iface_info=$(docker compose exec client ip -j addr show "$iface")

updated_ip=$(<<<"$iface_info" jq -r '.[0].addr_info[0].local')

if [[ "$updated_ip" != "$new_ip" ]] ; then
    echo "Failed to update IP"
    exit 1
fi

echo ""
echo "====================================================================="
echo "Post float ping server"
echo "====================================================================="
docker compose exec client ping -W 1 -c 3 server

echo ""
echo "IP addressed change ok, running tests"

./run-simple-test.sh

