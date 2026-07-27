#!/usr/bin/env bash
set -euo pipefail
: "${DEVICE_SERIAL:?missing DEVICE_SERIAL}"
: "${R1_MGMT_IP:?missing R1_MGMT_IP}"
install -d -m 0700 -o www-data -g www-data /var/www/.ssh
install -m 0600 -o www-data -g www-data /run/carrier/diag_key /var/www/.ssh/id_ed25519
: >/var/www/.ssh/known_hosts
for _ in $(seq 1 30); do
  ssh-keyscan -T 3 -H "$R1_MGMT_IP" \
    >/var/www/.ssh/known_hosts 2>/dev/null && break
  sleep 2
done
test -s /var/www/.ssh/known_hosts
chown www-data:www-data /var/www/.ssh/known_hosts
chmod 0600 /var/www/.ssh/known_hosts
cat >/etc/snmp/snmpd.conf <<'EOF'
agentAddress udp:161
sysLocation DakshinLink Network Operations Centre
sysContact noc@dakshinlink.example
rocommunity public
pass .1.3.6.1.2.1.47.1.1.1.1.11 /usr/local/sbin/serial-mib.sh
dontLogTCPWrappersConnects yes
EOF
mkdir -p /var/log/apache2 /var/log/carrier-portal
touch /var/log/carrier-portal/audit.jsonl
chown -R www-data:adm /var/log/apache2 /var/log/carrier-portal
snmpd -f -Lo -C -c /etc/snmp/snmpd.conf \
  >>/var/log/carrier-portal/snmpd.log 2>&1 &
exec apachectl -D FOREGROUND
