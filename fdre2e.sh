#!/bin/bash

# Arkfile Helper Script: Full Development Reset & End-to-End Test Script

set -e

# Check if running as root first
if [ "$EUID" -ne 0 ]; then
    echo -e "\033[0;31mERROR: This script must be run with sudo privileges\033[0m"
    exit 1
fi

echo "WARNING: This script deletes ALL Arkfile data from the local system!"
echo "Initiating FULL DEV RESET in 5 seconds..."
echo "...5"
sleep 1
echo "...4"
sleep 1
echo "...3"
sleep 1
echo "...2"
sleep 1
echo "...1"
sleep 1
echo "...Go!"
sleep 2

echo " "
echo "--- INIT dev-reset.sh ---"

echo "NUKE" | bash scripts/dev-reset.sh

echo " "
sleep 3

echo "--- INIT e2e-test.sh ---"

bash scripts/testing/e2e-test.sh

echo " "
sleep 3

echo "--- INIT e2e-playwright.sh ---"

bash scripts/testing/e2e-playwright.sh

echo " "
echo "--- END ---"

