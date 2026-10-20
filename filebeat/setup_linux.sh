#!/usr/bin/env bash
# ==============================================================================
# Linux Filebeat Automated Installer & Threat Log Shipper
# Project: Centralized Log Monitoring and Threat Detection System
# ==============================================================================

set -euo pipefail

VERSION="8.11.3"
ELK_HOST="${1:-192.168.0.113}"

echo "======================================================================"
echo "  Deploying Filebeat ${VERSION} to Linux Endpoint"
echo "  Forwarding logs to Logstash at: ${ELK_HOST}:5044"
echo "======================================================================"

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (e.g. sudo bash setup_linux.sh <ELK_HOST_IP>)"
  exit 1
fi

# 1. Install Filebeat repository or package
if command -v apt-get >/dev/null 2>&1; then
    echo "[*] Detected Debian/Ubuntu. Installing dependencies and Elastic GPG key..."
    apt-get update -y && apt-get install -y wget curl gnupg
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor --yes -o /usr/share/keyrings/elasticsearch-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update -y
    apt-get install -y filebeat=${VERSION} || apt-get install -y filebeat
elif command -v yum >/dev/null 2>&1; then
    echo "[*] Detected RHEL/CentOS/Rocky. Installing Filebeat..."
    rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
    cat <<EOF > /etc/yum.repos.d/elastic.repo
[elastic-8.x]
name=Elastic repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
    yum install -y filebeat-${VERSION} || yum install -y filebeat
fi

# 2. Deploy Configuration
echo "[*] Configuring /etc/filebeat/filebeat.yml..."
cat <<EOF > /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: filestream
    id: linux-auth-logs
    enabled: true
    paths:
      - /var/log/auth.log
      - /var/log/secure
    fields:
      log_type: linux_auth
    fields_under_root: true
    ignore_older: 72h

processors:
  - add_host_metadata:
      when.not.has_fields: ['host']
  - add_fields:
      fields:
        log_source_os: "Linux"

output.logstash:
  hosts: ["${ELK_HOST}:5044"]

setup.template.enabled: false
setup.ilm.enabled: false
EOF

chmod 600 /etc/filebeat/filebeat.yml

# 3. Enable and Start Filebeat Service
echo "[*] Enabling and starting Filebeat service..."
systemctl daemon-reload
systemctl enable filebeat
systemctl restart filebeat

echo "[+] Filebeat status:"
systemctl status filebeat --no-pager || true

echo "======================================================================"
echo "[+] Filebeat deployment complete! Auth logs are shipping to Logstash."
echo "======================================================================"
