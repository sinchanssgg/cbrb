#!/bin/bash
set -euo pipefail

# node_id, n, t, c, payload_bytes, controller_addr, tls_*, self_ip
# are substituted by Terraform's templatefile().

apt-get update
apt-get install -y curl build-essential pkg-config libssl-dev git

# Install Rust if not present
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi

# Fetch the binary (replace with your artifact URL or GCS bucket)
# curl -L "https://storage.googleapis.com/YOUR_BUCKET/node-linux-amd64" -o /usr/local/bin/node
# chmod +x /usr/local/bin/node

# Write TLS material
mkdir -p /etc/crbb
echo "${tls_ca_b64}"   | base64 -d > /etc/crbb/ca.pem
echo "${tls_cert_b64}" | base64 -d > /etc/crbb/cert.pem
echo "${tls_key_b64}"  | base64 -d > /etc/crbb/key.pem

# Build the config
cat > /etc/crbb/config.json <<EOF
{
  "node_id": ${node_id},
  "n": ${n},
  "t": ${t},
  "c": ${c},
  "message_len": ${payload_bytes},
  "sender_id": 0,
  "mid": [0, 1],
  "payload": [],
  "peers": [],
  "controller_addr": "${controller_addr}",
  "tls_cert_pem": "$(base64 -w0 /etc/crbb/cert.pem)",
  "tls_key_pem":  "$(base64 -w0 /etc/crbb/key.pem)",
  "ca_cert_pem":  "$(base64 -w0 /etc/crbb/ca.pem)",
  "auth_delay_ms": 1000
}
EOF

# (Peer list is filled by run_sweep.sh after IPs are known.)
echo "startup done for node ${node_id} (${self_ip})" > /var/log/crbb-startup.log