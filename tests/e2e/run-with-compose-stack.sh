#!/bin/bash

set -euo pipefail

function run_hooks() {
    local hook=$1; shift
    local hookdir="/etc/e2e/hooks/${hook}.d"

    if [ -e "$hookdir" ] ; then
        echo ""
        echo "====================================================================="
        echo "RUNNING HOOKS: $hookdir"
        echo "====================================================================="
        run-parts --exit-on-error --verbose -- "$hookdir"
    fi
}

function on_exit() {
    local rv=$?

    echo ""
    echo "====================================================================="
    echo "DOCKER STATUS"
    echo "====================================================================="
    docker ps

    echo ""
    echo "====================================================================="
    echo "STOP CONTAINERS"
    echo "====================================================================="
    # Docker compose will send sigterm to containers on stop. Logs will still be
    # available afterwards, until compose down. 
    # With stop and down, we can capture logs during container termination.
    docker compose stop

    # Individually so they aren't interleaved
    echo ""
    echo "====================================================================="
    echo "CONTAINER LOGS"
    echo "====================================================================="

    docker compose logs client
    echo ""
    docker compose logs server
    echo ""
    docker compose logs nginx

    run_hooks pre-compose-down
    echo ""
    echo "====================================================================="
    echo "TEAR DOWN COMPOSE STACK"
    echo "====================================================================="
    docker compose down --remove-orphans
    run_hooks post-compose-down
    
    if [ $rv -ne 0 ] ; then
        echo ""
        echo "Tests failed!"
    fi

    exit $rv
}

if [ $# -lt 1 ] ; then
    echo "A test script to be run is required"
    exit 1
fi
test_script="$1" ; shift

trap on_exit EXIT

run_hooks pre-compose-up
echo ""
echo "====================================================================="
echo "SETUP COMPOSE STACK"
echo "====================================================================="
docker compose up --detach --wait --wait-timeout 15
run_hooks post-compose-up

echo ""
docker ps

run_hooks pre-test
# Run the test script.
echo ""
echo "====================================================================="
echo "RUNNING $test_script $*"
echo "====================================================================="
$test_script "$@"
run_hooks post-test
