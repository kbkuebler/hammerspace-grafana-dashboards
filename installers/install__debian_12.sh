#!/bin/bash
#
# Install needed packages for both prometheus and grafana to operate on single
# debian 12 based host
#
# run the script with sudo
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo or as root. Exiting."
    exit 1
fi

SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Fail on error, show all commands run and output
set -e -x -u

# Debian 12 has a new enough prometheus, use what is available
apt update
apt install -y prometheus gpg 

# Grafana is in it's own repo
# https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/
apt install -y apt-transport-https software-properties-common wget
mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list

apt update
apt install -y grafana
systemctl daemon-reload
systemctl enable grafana-server
systemctl start grafana-server
systemctl status grafana-server


# Install items needed for automated configuration tooling
apt install -y python3-requests python3-yaml
