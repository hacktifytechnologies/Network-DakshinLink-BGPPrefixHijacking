#!/usr/bin/env bash
set -euo pipefail
test -s /etc/frr/frr.conf
sed -i 's/^zebra=.*/zebra=yes/; s/^bgpd=.*/bgpd=yes/' /etc/frr/daemons
chown frr:frr /etc/frr/frr.conf
chmod 0640 /etc/frr/frr.conf
mkdir -p /run/frr /run/sshd /var/log/carrier /root/.ssh
chown frr:frr /run/frr /var/log/carrier
if [[ -s /run/carrier/authorized_keys ]]; then
  install -m 0600 /run/carrier/authorized_keys /root/.ssh/authorized_keys
fi
cat >/etc/ssh/sshd_config.d/carrier.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
X11Forwarding no
PrintMotd no
LogLevel VERBOSE
EOF
/usr/lib/frr/frrinit.sh start
/usr/sbin/sshd -E /var/log/carrier/auth.log
if [[ "${CAPTURE_TRANSIT:-0}" == "1" ]]; then
  touch /var/log/carrier/transit.pcap
  tcpdump -i any -U -n -s 0 \
    -w /var/log/carrier/transit.pcap \
    '(tcp port 21 or tcp port 22 or tcp port 179)' \
    >>/var/log/carrier/tcpdump-console.log 2>&1 &
  echo "$!" >/run/carrier-tcpdump.pid
fi
trap '/usr/lib/frr/frrinit.sh stop >/dev/null 2>&1 || true' EXIT
while :; do
  pgrep -x bgpd >/dev/null
  pgrep -x zebra >/dev/null
  sleep 3
done
