#!/usr/bin/env bash
set -euo pipefail
: "${FTP_USERNAME:?missing FTP_USERNAME}"
: "${FTP_PASSWORD:?missing FTP_PASSWORD}"
: "${FTP_SERVER_IP:?missing FTP_SERVER_IP}"
: "${CLIENT_GATEWAY:?missing CLIENT_GATEWAY}"
ip route replace default via "$CLIENT_GATEWAY"
log=/var/log/carrier/client-transfer.jsonl
touch "$log"
sleep 15
while :; do
  started="$(date -Is)"
  if curl --silent --show-error --fail --max-time 15 \
       --ftp-method nocwd \
       --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
       "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt" \
       -o /dev/null; then
    printf '{"timestamp":"%s","event":"ftp_transfer","server":"%s","status":"success"}\n' \
      "$started" "$FTP_SERVER_IP" >>"$log"
  else
    rc=$?
    printf '{"timestamp":"%s","event":"ftp_transfer","server":"%s","status":"failure","curl_rc":%s}\n' \
      "$started" "$FTP_SERVER_IP" "$rc" >>"$log"
  fi
  sleep "$((20 + RANDOM % 16))"
done
