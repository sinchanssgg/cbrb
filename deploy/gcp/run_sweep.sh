#!/usr/bin/env bash
# Drive a full sweep against a Terraform-provisioned cluster.
# Assumes `terraform output -json node_ips` gives the array of IPs.

set -euo pipefail

if ! command -v terraform >/dev/null; then
  echo "terraform not found" >&2; exit 1
fi
if ! command -v jq >/dev/null; then
  echo "jq not found (apt install jq)" >&2; exit 1
fi

cd "$(dirname "$0")"

IPS=($(terraform output -json node_ips | jq -r '.[]'))
N=${#IPS[@]}
echo "cluster: $N nodes"

# Build peer list
PEERS="["
for i in "${!IPS[@]}"; do
  if [ "$i" -gt 0 ]; then PEERS+=","; fi
  PEERS+="{\"id\": $i, \"addr\": \"${IPS[$i]}:19000\"}"
done
PEERS+="]"

# Push the peer list to each node via gcloud SSH
for i in "${!IPS[@]}"; do
  echo "configuring node $i"
  gcloud compute ssh "crbb-node-$i" --zone us-east1-b --command \
    "sudo jq '.peers = $PEERS' /etc/crbb/config.json > /tmp/cfg && \
     sudo mv /tmp/cfg /etc/crbb/config.json && \
     sudo systemctl restart crbb"
done

echo "experiment running; collect metrics from controller"