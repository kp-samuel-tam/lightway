#!/bin/bash

set -euo pipefail

physical_ip=$(ip --json addr show eth0 | jq -r '.[0].addr_info[0].local')
tunnel_ip=$(ip --json addr show lightway | jq -r '.[0].addr_info[0].local')

# --- Test

echo ""
echo "====================================================================="
echo "STARTING ping TEST"
echo "====================================================================="

ping -W 1 -c 3 nginx

echo ""
echo "====================================================================="
echo "STARTING curl TEST"
echo "====================================================================="

REPLY=$(curl http://nginx)
IP=$(<<<"$REPLY" jq -e -r '.ip // "fail"' || echo "invalid-json")

echo ""
echo "Local physical IP is ${physical_ip}"
echo "Local tunnel IP is ${tunnel_ip}"
echo ""
echo "curl replied: $REPLY"
echo "IP: $IP"
echo ""

case $IP in
    "fail")
        echo "Invalid response from nginx"
        exit 1
	;;
    "invalid-json")
	echo "JSON response did not contain ip key"
	exit 1
	;;

    "${tunnel_ip}")
        echo "nginx saw our real tunnel IP!"
        exit 1
        ;;
    "${physical_ip}")
        echo "nginx saw our real physical IP!"
        exit 1
        ;;

    "10.0."*)
        echo "nginx saw a backend network IP address -- all good!"
        ;;

    *)
        echo "nginx unexpectedly saw IP ${IP}"
        exit 1
        ;;
esac

echo ""
echo "====================================================================="
echo "STARTING forward iperf TEST (TCP)"
echo "====================================================================="
retry --times=3 --delay=1 -- iperf3 -t 10 -b 10M -c iperf

echo ""
echo "====================================================================="
echo "STARTING forward iperf TEST (UDP)"
echo "====================================================================="
retry --times=3 --delay=1 -- iperf3 -t 10 -u -b 10M -c iperf

echo ""
echo "====================================================================="
echo "STARTING reverse iperf TEST (TCP)"
echo "====================================================================="
retry --times=3 --delay=1 -- iperf3 -t 10 -b 10M -c iperf -R

echo ""
echo "====================================================================="
echo "STARTING reverse iperf TEST (UDP)"
echo "====================================================================="
retry --times=3 --delay=1 -- iperf3 -t 10 -u -b 10M -c iperf -R

echo ""
echo "====================================================================="
echo "TESTS COMPLETE"
echo "====================================================================="
