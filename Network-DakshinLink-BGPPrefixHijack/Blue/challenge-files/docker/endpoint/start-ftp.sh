#!/usr/bin/env bash
set -euo pipefail
: "${FTP_USERNAME:?missing FTP_USERNAME}"
: "${FTP_PASSWORD:?missing FTP_PASSWORD}"
: "${FTP_GATEWAY:?missing FTP_GATEWAY}"
getent passwd "$FTP_USERNAME" >/dev/null 2>&1 \
  || useradd -m -d "/srv/ftp/${FTP_USERNAME}" -s /bin/bash "$FTP_USERNAME"
printf '%s:%s\n' "$FTP_USERNAME" "$FTP_PASSWORD" | chpasswd
home="/srv/ftp/${FTP_USERNAME}"
install -d -m 0750 -o "$FTP_USERNAME" -g "$FTP_USERNAME" "$home/archive"
cat >"$home/archive/network-operations-archive.txt" <<'EOF'
DakshinLink inter-carrier operations archive
Classification: training network operations data
The archive confirms that the protected FTP workflow remains functional.
EOF
chown "$FTP_USERNAME:$FTP_USERNAME" "$home/archive/network-operations-archive.txt"
mkdir -p /run/sshd
cat >/etc/ssh/sshd_config.d/carrier-ftp.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding no
LogLevel VERBOSE
EOF
/usr/sbin/sshd -E /var/log/carrier/ssh.log
cat >/etc/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO
background=NO
anonymous_enable=NO
local_enable=YES
write_enable=NO
local_umask=077
use_localtime=YES
xferlog_enable=YES
xferlog_file=/var/log/carrier/vsftpd.log
log_ftp_protocol=YES
connect_from_port_20=YES
seccomp_sandbox=NO
pam_service_name=vsftpd
local_root=$home
pasv_enable=NO
EOF
ip route replace default via "$FTP_GATEWAY"
exec /usr/sbin/vsftpd /etc/vsftpd.conf
