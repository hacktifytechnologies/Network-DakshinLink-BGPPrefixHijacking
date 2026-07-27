#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  docker.io graphviz jq curl snmp netcat-openbsd \
  python3 openssl iproute2 iptables ca-certificates
systemctl enable --now docker.service
for tool in docker dot jq curl snmpwalk python3 openssl ip ss systemctl; do
  command -v "$tool" >/dev/null
done
echo "Dependencies installed successfully"
