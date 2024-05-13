#!/bin/bash

set -euo pipefail


docker compose exec client ./run-test-inside.sh
