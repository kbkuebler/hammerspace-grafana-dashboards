#!/bin/bash
# This script builds a prometheus.yaml configuration

# Prompt for general info
read -p "Enter domain name (e.g. ourcompany.com): " DOMAIN
read -p "Enter cluster name (e.g. hscluster): " CLUSTER

# Anvil node info
read -p "Enter Anvil node names (space separated, e.g. anvil-1 anvil-2): " -a ANVILS
declare -A ANVIL_IPS
for node in "${ANVILS[@]}"; do
  read -p "Enter IP address for Anvil node '$node': " ip
  ANVIL_IPS["$node"]="$ip"
done

# DSX node info
read -p "Enter DSX node names (space separated, e.g. dsx-1 dsx-2 dsx-3): " -a DSXS
declare -A DSX_IPS
for node in "${DSXS[@]}"; do
  read -p "Enter IP address for DSX node '$node': " ip
  DSX_IPS["$node"]="$ip"
done

# Define the output file name
OUTPUT_FILE="prometheus.yaml"

# Begin writing the configuration file
cat > "$OUTPUT_FILE" <<EOF
scrape_configs:
- job_name: prometheus
  static_configs:
  - labels:
      node_type: prometheus
    targets:
    - localhost:9090
### Add your hammerspace cluster
- job_name: cluster
  static_configs:
  - labels:
      cluster: ${CLUSTER}.${DOMAIN}
      instance: ${CLUSTER}.${DOMAIN}
      node_type: clusterip
    targets:
    - 10.0.0.71:9101
    - 10.0.0.71:9102
    - 10.0.0.71:9103
EOF

# Append Anvil nodes configuration.
{
  echo "- job_name: anvil_nodes"
  echo "  static_configs:"
} >> "$OUTPUT_FILE"

for node in "${ANVILS[@]}"; do
  ip="${ANVIL_IPS[$node]}"
  {
    echo "  - labels:"
    echo "      cluster: ${CLUSTER}.${DOMAIN}"
    echo "      instance: ${CLUSTER}-${node}.${DOMAIN}"
    echo "      node_type: anvil"
    echo "    targets:"
    echo "    - ${ip}:9100"
  } >> "$OUTPUT_FILE"
done

# Append DSX nodes configuration.
{
  echo "- job_name: dsx_nodes"
  echo "  static_configs:"
} >> "$OUTPUT_FILE"

for node in "${DSXS[@]}"; do
  ip="${DSX_IPS[$node]}"
  {
    echo "  - labels:"
    echo "      cluster: ${CLUSTER}.${DOMAIN}"
    echo "      instance: ${CLUSTER}-${node}.${DOMAIN}"
    echo "      node_type: dsx"
    echo "    targets:"
    echo "    - ${ip}:9100"
    echo "    - ${ip}:9105"
  } >> "$OUTPUT_FILE"
done

echo "prometheus.yaml has been generated."

