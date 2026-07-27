#!/usr/bin/env bash
# NWR-CARRIER-01 - DakshinLink Route Interception
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo "Run as root"; exit 1; }

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILES_DIR="${BASE_DIR}/challenge-files"
SLUG="carrier-dakshinlink-route-interception"
ROOT_DIR="/opt/network-challenges/${SLUG}"
CONFIG_DIR="${ROOT_DIR}/config"
RUNTIME_DIR="${ROOT_DIR}/runtime"
TELEMETRY_DIR="${ROOT_DIR}/telemetry"
WEBROOT_DIR="${ROOT_DIR}/webroot"
ORG1="DakshinLink Networks"
ORG2="Vindhya Broadband"
ORG3="Sahyadri Data Exchange"
# Participant-facing ports are intentionally stable across deployments.
# Internal topology addresses remain dynamically allocated to avoid collisions.
PUBLIC_HTTP_PORT=18080
PUBLIC_SNMP_PORT=18161

log(){ printf '[SETUP] %s\n' "$*"; }
fail(){ printf '[FAIL] %s\n' "$*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1; }
for tool in docker dot jq curl snmpwalk python3 openssl ip ss systemctl timeout; do
  need "$tool" || bash "${BASE_DIR}/deps.sh"
done
systemctl is-active --quiet docker.service || systemctl start docker.service

tcp_port_busy(){
  ss -lntH | awk '{print $4}' | grep -Eq "(^|:)${1}$"
}
udp_port_busy(){
  ss -lunH | awk '{print $4}' | grep -Eq "(^|:)${1}$"
}
challenge_portal_owns_mapping(){
  local port="$1" target="$2"
  docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
    | awk -v port="$port" -v target="$target" '
        $1 ~ /^carrier-portal-[a-f0-9]{8}$/ &&
        index($0, ":" port "->" target) { found=1 }
        END { exit(found ? 0 : 1) }
      '
}
preflight_public_ports(){
  if tcp_port_busy "$PUBLIC_HTTP_PORT" \
     && ! challenge_portal_owns_mapping "$PUBLIC_HTTP_PORT" "80/tcp"; then
    fail "Fixed web port ${PUBLIC_HTTP_PORT}/tcp is already in use by another application"
  fi
  if udp_port_busy "$PUBLIC_SNMP_PORT" \
     && ! challenge_portal_owns_mapping "$PUBLIC_SNMP_PORT" "161/udp"; then
    fail "Fixed SNMP port ${PUBLIC_SNMP_PORT}/udp is already in use by another application"
  fi
}
preflight_public_ports

required_files=(
  "$FILES_DIR/templates/r1-frr.conf.template"
  "$FILES_DIR/templates/r2-frr.conf.template"
  "$FILES_DIR/templates/r3-frr.conf.template"
  "$FILES_DIR/templates/topology.dot.template"
  "$FILES_DIR/portal/common.php"
  "$FILES_DIR/portal/index.php"
  "$FILES_DIR/portal/dashboard.php"
  "$FILES_DIR/portal/diag.php"
  "$FILES_DIR/portal/logout.php"
  "$FILES_DIR/portal/style.css"
  "$FILES_DIR/portal/tickets.php.template"
  "$FILES_DIR/portal/doc/index.php"
  "$FILES_DIR/portal/tools/remote.php"
  "$FILES_DIR/portal/debug/index.php"
  "$FILES_DIR/docker/portal/serial-mib.sh"
  "$FILES_DIR/docker/portal/apache-carrier.conf"
  "$FILES_DIR/systemd/frr.service.template"
  "$FILES_DIR/systemd/r2.service.template"
  "$FILES_DIR/systemd/r3.service.template"
  "$FILES_DIR/systemd/portal.service.template"
  "$FILES_DIR/systemd/ftp.service.template"
  "$FILES_DIR/systemd/client.service.template"
)
for required_file in "${required_files[@]}"; do
  [[ -f "$required_file" ]] || fail "Missing required scenario file: $required_file"
done

cleanup_previous(){
  local old="${RUNTIME_DIR}/scoring.env"
  if [[ -r "$old" ]]; then
    # shellcheck disable=SC1090
    . "$old"
    for unit in frr.service \
      "${SLUG}-r2.service" "${SLUG}-r3.service" \
      "${SLUG}-portal.service" "${SLUG}-ftp.service" "${SLUG}-client.service"; do
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    for var in R1_CONTAINER R2_CONTAINER R3_CONTAINER PORTAL_CONTAINER FTP_CONTAINER CLIENT_CONTAINER; do
      name="${!var:-}"
      [[ "$name" =~ ^carrier-[a-z0-9-]+$ ]] && docker rm -f "$name" >/dev/null 2>&1 || true
    done
    for var in MGMT_NETWORK R1R2_NETWORK R1R3_NETWORK R2R3_NETWORK CLIENT_NETWORK FTP_NETWORK; do
      name="${!var:-}"
      [[ "$name" =~ ^carrier-[a-z0-9-]+$ ]] && docker network rm "$name" >/dev/null 2>&1 || true
    done
  fi
  # A failed first deployment may stop before scoring.env is written.
  # Remove only resources whose names match this challenge's generated
  # names so the next setup run starts cleanly.
  local stale
  while IFS= read -r stale; do
    [[ "$stale" =~ ^carrier-(r1|r2|r3|portal|ftp|client|router-selftest-(r1|r2|r3)|portal-selftest|ftp-selftest)-[a-f0-9]{8}$ ]] || continue
    docker rm -f "$stale" >/dev/null 2>&1 || true
  done < <(docker ps -a --format '{{.Names}}')
  while IFS= read -r stale; do
    [[ "$stale" =~ ^carrier-(mgmt|r1r2|r1r3|r2r3|client-net|ftp-net)-[a-f0-9]{8}$ ]] || continue
    docker network rm "$stale" >/dev/null 2>&1 || true
  done < <(docker network ls --format '{{.Name}}')
  rm -f "/etc/systemd/system/frr.service"
  rm -f "/etc/systemd/system/${SLUG}-"{r2,r3,portal,ftp,client}.service
  systemctl daemon-reload
  systemctl reset-failed \
    frr.service \
    "${SLUG}-r2.service" "${SLUG}-r3.service" \
    "${SLUG}-portal.service" "${SLUG}-ftp.service" \
    "${SLUG}-client.service" >/dev/null 2>&1 || true
}
cleanup_previous

# Docker's userland proxy can briefly retain a published port after container
# removal. Do not create the next instance until both fixed ports are free.
for _ in $(seq 1 15); do
  if ! tcp_port_busy "$PUBLIC_HTTP_PORT" \
     && ! udp_port_busy "$PUBLIC_SNMP_PORT"; then
    break
  fi
  sleep 1
done
tcp_port_busy "$PUBLIC_HTTP_PORT" \
  && fail "Fixed web port ${PUBLIC_HTTP_PORT}/tcp was not released by the previous deployment"
udp_port_busy "$PUBLIC_SNMP_PORT" \
  && fail "Fixed SNMP port ${PUBLIC_SNMP_PORT}/udp was not released by the previous deployment"

install -d -m 0750 "$ROOT_DIR" "$CONFIG_DIR" "$TELEMETRY_DIR"
install -d -m 0700 "$RUNTIME_DIR"
install -d -m 0755 "$WEBROOT_DIR"
for area in r1 r2 r3 portal ftp client; do
  install -d -m 0750 "$TELEMETRY_DIR/$area"
done
install -d -m 0755 "$WEBROOT_DIR/doc" "$WEBROOT_DIR/tools" "$WEBROOT_DIR/debug"

INSTANCE_ID="$(openssl rand -hex 4)"
DEVICE_SERIAL="DLK-$(openssl rand -hex 6 | tr '[:lower:]' '[:upper:]')"
FTP_USERNAME="ops_$(openssl rand -hex 3)"
FTP_PASSWORD="$(openssl rand -hex 10)"
PORTAL_BRAND="DakshinLink NOC Portal"

R1_CONTAINER="carrier-r1-${INSTANCE_ID}"
R2_CONTAINER="carrier-r2-${INSTANCE_ID}"
R3_CONTAINER="carrier-r3-${INSTANCE_ID}"
PORTAL_CONTAINER="carrier-portal-${INSTANCE_ID}"
FTP_CONTAINER="carrier-ftp-${INSTANCE_ID}"
CLIENT_CONTAINER="carrier-client-${INSTANCE_ID}"
R1_HOSTNAME="dl-edge-${INSTANCE_ID}"
R2_HOSTNAME="vb-edge-${INSTANCE_ID}"
R3_HOSTNAME="sdx-edge-${INSTANCE_ID}"

AS1="$(shuf -i 64512-65534 -n 1)"
while :; do AS2="$(shuf -i 64512-65534 -n 1)"; [[ "$AS2" != "$AS1" ]] && break; done
while :; do
  AS3="$(shuf -i 64512-65534 -n 1)"
  [[ "$AS3" != "$AS1" && "$AS3" != "$AS2" ]] && break
done

network_candidate(){
  local prefix="$1" second third fourth
  second="$(shuf -i 64-223 -n 1)"
  third="$(shuf -i 1-254 -n 1)"
  if [[ "$prefix" == 24 ]]; then
    printf '10.%s.%s.0/24\n' "$second" "$third"
  else
    fourth="$(( $(shuf -i 0-31 -n 1) * 8 ))"
    printf '10.%s.%s.%s/29\n' "$second" "$third" "$fourth"
  fi
}
allocate_network(){
  local name="$1" prefix="$2" scope="$3" candidate
  for _ in $(seq 1 160); do
    candidate="$(network_candidate "$prefix")"
    if [[ "$scope" == internal ]]; then
      docker network create --internal --driver bridge --subnet "$candidate" "$name" >/dev/null 2>&1 || continue
    else
      docker network create --driver bridge --subnet "$candidate" "$name" >/dev/null 2>&1 || continue
    fi
    printf '%s\n' "$candidate"
    return
  done
  return 1
}
MGMT_NETWORK="carrier-mgmt-${INSTANCE_ID}"
R1R2_NETWORK="carrier-r1r2-${INSTANCE_ID}"
R1R3_NETWORK="carrier-r1r3-${INSTANCE_ID}"
R2R3_NETWORK="carrier-r2r3-${INSTANCE_ID}"
CLIENT_NETWORK="carrier-client-net-${INSTANCE_ID}"
FTP_NETWORK="carrier-ftp-net-${INSTANCE_ID}"
MGMT_SUBNET="$(allocate_network "$MGMT_NETWORK" 29 external)" || fail "Unable to allocate management network"
R1R2_SUBNET="$(allocate_network "$R1R2_NETWORK" 29 internal)" || fail "Unable to allocate r1-r2 network"
R1R3_SUBNET="$(allocate_network "$R1R3_NETWORK" 29 internal)" || fail "Unable to allocate r1-r3 network"
R2R3_SUBNET="$(allocate_network "$R2R3_NETWORK" 29 internal)" || fail "Unable to allocate r2-r3 network"
CLIENT_SUBNET="$(allocate_network "$CLIENT_NETWORK" 24 internal)" || fail "Unable to allocate client network"
FTP_SUBNET="$(allocate_network "$FTP_NETWORK" 24 internal)" || fail "Unable to allocate FTP network"

address(){
  python3 - "$1" "$2" <<'PY'
import ipaddress, sys
network = ipaddress.ip_network(sys.argv[1], strict=False)
print(network.network_address + int(sys.argv[2]))
PY
}
PORTAL_MGMT_IP="$(address "$MGMT_SUBNET" 2)"
R1_MGMT_IP="$(address "$MGMT_SUBNET" 3)"
R1_R1R2_IP="$(address "$R1R2_SUBNET" 2)"
R2_R1R2_IP="$(address "$R1R2_SUBNET" 3)"
R1_R1R3_IP="$(address "$R1R3_SUBNET" 2)"
R3_R1R3_IP="$(address "$R1R3_SUBNET" 3)"
R2_R2R3_IP="$(address "$R2R3_SUBNET" 2)"
R3_R2R3_IP="$(address "$R2R3_SUBNET" 3)"
R2_CLIENT_IP="$(address "$CLIENT_SUBNET" 2)"
CLIENT_IP="$(address "$CLIENT_SUBNET" 10)"
R3_FTP_IP="$(address "$FTP_SUBNET" 2)"
FTP_SERVER_IP="$(address "$FTP_SUBNET" 10)"
HIJACK_PREFIX_A="$(python3 - "$FTP_SUBNET" <<'PY'
import ipaddress, sys
print(list(ipaddress.ip_network(sys.argv[1]).subnets(prefixlen_diff=1))[0])
PY
)"
HIJACK_PREFIX_B="$(python3 - "$FTP_SUBNET" <<'PY'
import ipaddress, sys
print(list(ipaddress.ip_network(sys.argv[1]).subnets(prefixlen_diff=1))[1])
PY
)"
R1_ROUTER_ID="$R1_R1R2_IP"
R2_ROUTER_ID="$R2_R1R2_IP"
R3_ROUTER_ID="$R3_R1R3_IP"

render(){
  local src="$1" dst="$2"
  sed \
    -e "s|@@ORG1@@|${ORG1}|g" -e "s|@@ORG2@@|${ORG2}|g" -e "s|@@ORG3@@|${ORG3}|g" \
    -e "s|@@AS1@@|${AS1}|g" -e "s|@@AS2@@|${AS2}|g" -e "s|@@AS3@@|${AS3}|g" \
    -e "s|@@R1_HOSTNAME@@|${R1_HOSTNAME}|g" -e "s|@@R2_HOSTNAME@@|${R2_HOSTNAME}|g" -e "s|@@R3_HOSTNAME@@|${R3_HOSTNAME}|g" \
    -e "s|@@R1_ROUTER_ID@@|${R1_ROUTER_ID}|g" -e "s|@@R2_ROUTER_ID@@|${R2_ROUTER_ID}|g" -e "s|@@R3_ROUTER_ID@@|${R3_ROUTER_ID}|g" \
    -e "s|@@R1_R1R2_IP@@|${R1_R1R2_IP}|g" -e "s|@@R2_R1R2_IP@@|${R2_R1R2_IP}|g" \
    -e "s|@@R1_R1R3_IP@@|${R1_R1R3_IP}|g" -e "s|@@R3_R1R3_IP@@|${R3_R1R3_IP}|g" \
    -e "s|@@R2_R2R3_IP@@|${R2_R2R3_IP}|g" -e "s|@@R3_R2R3_IP@@|${R3_R2R3_IP}|g" \
    -e "s|@@CLIENT_SUBNET@@|${CLIENT_SUBNET}|g" -e "s|@@FTP_SUBNET@@|${FTP_SUBNET}|g" \
    "$src" >"$dst"
}
render "$FILES_DIR/templates/r1-frr.conf.template" "$CONFIG_DIR/r1-frr.conf"
render "$FILES_DIR/templates/r2-frr.conf.template" "$CONFIG_DIR/r2-frr.conf"
render "$FILES_DIR/templates/r3-frr.conf.template" "$CONFIG_DIR/r3-frr.conf"
render "$FILES_DIR/templates/topology.dot.template" "$CONFIG_DIR/topology.dot"
render "$FILES_DIR/portal/tickets.php.template" "$WEBROOT_DIR/tickets.php"
dot -Tpng "$CONFIG_DIR/topology.dot" -o "$WEBROOT_DIR/doc/diagram_for_tac.png"
cp "$FILES_DIR/portal/"{common.php,index.php,dashboard.php,diag.php,logout.php,style.css} "$WEBROOT_DIR/"
cp "$FILES_DIR/portal/doc/index.php" "$WEBROOT_DIR/doc/index.php"
cp "$FILES_DIR/portal/tools/remote.php" "$WEBROOT_DIR/tools/remote.php"
cp "$FILES_DIR/portal/debug/index.php" "$WEBROOT_DIR/debug/index.php"
python3 - "$WEBROOT_DIR/doc/error_codes.pdf" <<'PY'
from pathlib import Path
import sys

output = Path(sys.argv[1])

def escaped(value):
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

commands = []

def line(x, y, text, font="F1", size=10):
    commands.append(
        f"BT /{font} {size} Tf {x} {y} Td ({escaped(text)}) Tj ET"
    )

line(44, 552, "DakshinLink Network Element Management", "F2", 18)
line(44, 532, "Technical Assistance Centre - Platform Error Codes", "F2", 12)
line(
    44,
    505,
    "Use this manual when an appliance displays a numbered platform alert.",
    "F1",
    9,
)
line(
    44,
    492,
    "Values identify support state only and may require independent verification.",
    "F1",
    9,
)
line(44, 462, "Code", "F2", 10)
line(112, 462, "Severity", "F2", 10)
line(190, 462, "Description and support action", "F2", 10)

entries = [
    (
        "45009",
        "Warning",
        [
            "The administrative account remains in the factory credential state.",
            "Use the chassis serial number as the temporary administrator password,",
            "then rotate the credential after enrolment.",
        ],
    ),
    (
        "45010",
        "Warning",
        [
            "The remote support licence has expired.",
            "Read-only monitoring remains accessible. Contact the TAC for renewal.",
        ],
    ),
    (
        "31004",
        "Info",
        [
            "A configuration recovery profile is present.",
            "Use the approved redeployment process before disruptive maintenance.",
        ],
    ),
    (
        "22017",
        "Info",
        [
            "An external routing adjacency was detected.",
            "Compare peer ownership with the current topology document.",
        ],
    ),
]

y = 438
for code, severity, details in entries:
    line(44, y, code, "F1", 9)
    line(112, y, severity, "F1", 9)
    for offset, detail in enumerate(details):
        line(190, y - (offset * 13), detail, "F1", 9)
    y -= max(56, len(details) * 13 + 22)

line(
    44,
    42,
    "Document classification: internal network operations.",
    "F2",
    8,
)
line(
    44,
    29,
    "This document intentionally contains no device serial, ASN, address or password.",
    "F1",
    8,
)

stream = ("\n".join(commands) + "\n").encode("latin-1")
objects = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    (
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] "
        b"/Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> "
        b"/Contents 6 0 R >>"
    ),
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
    + stream
    + b"endstream",
]

pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
offsets = [0]
for number, obj in enumerate(objects, start=1):
    offsets.append(len(pdf))
    pdf.extend(f"{number} 0 obj\n".encode())
    pdf.extend(obj)
    pdf.extend(b"\nendobj\n")
xref = len(pdf)
pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode())
pdf.extend(b"0000000000 65535 f \n")
for offset in offsets[1:]:
    pdf.extend(f"{offset:010d} 00000 n \n".encode())
pdf.extend(
    (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n"
    ).encode()
)
output.write_bytes(pdf)
PY

rm -f "$RUNTIME_DIR/portal_diag_key" "$RUNTIME_DIR/portal_diag_key.pub"
ssh-keygen -q -t ed25519 -N '' -f "$RUNTIME_DIR/portal_diag_key"
cp "$RUNTIME_DIR/portal_diag_key.pub" "$CONFIG_DIR/r1-authorized_keys"
chmod 0600 "$RUNTIME_DIR/portal_diag_key" "$CONFIG_DIR/r1-authorized_keys"

ROUTER_IMAGE="dakshinlink-router:v3.0.8"
PORTAL_IMAGE="dakshinlink-portal:v3.0.8"
ENDPOINT_IMAGE="dakshinlink-endpoint:v3.0.8"

# Build the router image from a runtime-owned context. Keeping the
# corrected bootstrap here makes this setup script sufficient even
# when it replaces setup.sh inside an older v3 package.
ROUTER_BUILD_DIR="${ROOT_DIR}/build/router"
install -d -m 0750 "$ROUTER_BUILD_DIR"
cat >"$ROUTER_BUILD_DIR/Dockerfile" <<'ROUTER_DOCKERFILE'
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      frr frr-pythontools openssh-server iproute2 iputils-ping \
      tcpdump procps netcat-openbsd ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /run/carrier /var/log/carrier /root/.ssh \
 && chmod 0700 /root/.ssh
COPY start-router.sh /usr/local/sbin/start-router.sh
RUN chmod 0755 /usr/local/sbin/start-router.sh
EXPOSE 22 179
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/start-router.sh"]
ROUTER_DOCKERFILE
cat >"$ROUTER_BUILD_DIR/start-router.sh" <<'ROUTER_BOOTSTRAP'
#!/usr/bin/env bash
set -Eeuo pipefail

ZEBRA_PID=""
BGPD_PID=""
SSHD_PID=""
TCPDUMP_PID=""

stop_children(){
  trap - EXIT
  local pid
  for pid in "$TCPDUMP_PID" "$SSHD_PID" "$BGPD_PID" "$ZEBRA_PID"; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    kill -TERM "$pid" >/dev/null 2>&1 || true
  done
  for pid in "$TCPDUMP_PID" "$SSHD_PID" "$BGPD_PID" "$ZEBRA_PID"; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    wait "$pid" >/dev/null 2>&1 || true
  done
}
trap stop_children EXIT
trap 'exit 0' INT TERM

startup_failure(){
  printf '[ROUTER-STARTUP-FAIL] %s\n' "$*" >&2
  ps -ef >&2 || true
  local log_file
  for log_file in \
    /var/log/carrier/zebra-console.log \
    /var/log/carrier/bgpd-console.log \
    /var/log/carrier/config-load.log \
    /var/log/carrier/frr.log \
    /var/log/carrier/auth.log; do
    [[ -s "$log_file" ]] || continue
    printf '[ROUTER-STARTUP-FAIL] Recent %s:\n' "$log_file" >&2
    tail -n 160 "$log_file" >&2 || true
  done
  if [[ -d /var/tmp/frr ]]; then
    while IFS= read -r log_file; do
      printf '[ROUTER-STARTUP-FAIL] Crash record %s:\n' "$log_file" >&2
      tail -n 160 "$log_file" >&2 || true
    done < <(find /var/tmp/frr -type f -name crashlog -print 2>/dev/null)
  fi
  exit 1
}

wait_for_daemon(){
  local daemon_name="$1" pid="$2" socket_path="$3"
  local _
  for _ in $(seq 1 30); do
    kill -0 "$pid" >/dev/null 2>&1 \
      || startup_failure "$daemon_name exited during startup"
    [[ -S "$socket_path" ]] && return 0
    sleep 1
  done
  startup_failure "$daemon_name did not create $socket_path"
}

test -s /run/carrier/bootstrap-frr.conf \
  || startup_failure "Missing FRR bootstrap configuration"
install -d -m 0775 -o frr -g frrvty /run/frr
install -d -m 0755 /run/sshd /var/tmp/frr
install -d -m 0750 -o frr -g frr /var/log/carrier
install -d -m 0700 /root/.ssh
find /run/frr /run/sshd -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + \
  >/dev/null 2>&1 || true
find /var/tmp/frr -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + \
  >/dev/null 2>&1 || true
install -m 0640 -o frr -g frr \
  /run/carrier/bootstrap-frr.conf /etc/frr/frr.conf
install -m 0640 -o frr -g frr /dev/null /etc/frr/zebra.conf
install -m 0640 -o frr -g frr /dev/null /etc/frr/bgpd.conf
cat >/etc/frr/vtysh.conf <<'EOF'
service integrated-vtysh-config
EOF
chown root:frrvty /etc/frr/vtysh.conf
chmod 0640 /etc/frr/vtysh.conf

if [[ -s /run/carrier/authorized_keys ]]; then
  install -m 0600 /run/carrier/authorized_keys /root/.ssh/authorized_keys
fi
ssh-keygen -A >/dev/null 2>&1
cat >/etc/ssh/sshd_config.d/carrier.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
X11Forwarding no
PrintMotd no
LogLevel VERBOSE
EOF

/usr/lib/frr/zebra \
  -F traditional -A 127.0.0.1 -s 90000000 \
  -f /etc/frr/zebra.conf --log stdout --log-level informational \
  >>/var/log/carrier/zebra-console.log 2>&1 &
ZEBRA_PID="$!"
wait_for_daemon "zebra" "$ZEBRA_PID" /run/frr/zebra.vty

/usr/lib/frr/bgpd \
  -F traditional -A 127.0.0.1 \
  -f /etc/frr/bgpd.conf --log stdout --log-level informational \
  >>/var/log/carrier/bgpd-console.log 2>&1 &
BGPD_PID="$!"
wait_for_daemon "bgpd" "$BGPD_PID" /run/frr/bgpd.vty

if ! vtysh -b >/var/log/carrier/config-load.log 2>&1; then
  startup_failure "FRR configuration load failed"
fi
if ! vtysh -c 'show version' >/dev/null 2>&1 \
   || ! vtysh -c 'show ip route' >/dev/null 2>&1 \
   || ! vtysh -c 'show bgp ipv4 unicast summary' >/dev/null 2>&1; then
  startup_failure "FRR operational checks failed after configuration load"
fi

if [[ "${STARTUP_SELFTEST:-0}" == "1" ]]; then
  exit 0
fi

/usr/sbin/sshd -D -e >>/var/log/carrier/auth.log 2>&1 &
SSHD_PID="$!"
sleep 1
kill -0 "$SSHD_PID" >/dev/null 2>&1 \
  || startup_failure "OpenSSH server exited during startup"

if [[ "${CAPTURE_TRANSIT:-0}" == "1" ]]; then
  touch /var/log/carrier/transit.pcap
  tcpdump -i any -U -n -s 0 \
    -w /var/log/carrier/transit.pcap \
    '(tcp port 21 or tcp port 22 or tcp port 179)' \
    >>/var/log/carrier/tcpdump-console.log 2>&1 &
  TCPDUMP_PID="$!"
  echo "$TCPDUMP_PID" >/run/carrier-tcpdump.pid
fi

while :; do
  kill -0 "$ZEBRA_PID" >/dev/null 2>&1 \
    || startup_failure "zebra stopped"
  kill -0 "$BGPD_PID" >/dev/null 2>&1 \
    || startup_failure "bgpd stopped"
  kill -0 "$SSHD_PID" >/dev/null 2>&1 \
    || startup_failure "OpenSSH server stopped"
  sleep 3
done
ROUTER_BOOTSTRAP
chmod 0755 "$ROUTER_BUILD_DIR/start-router.sh"

PORTAL_BUILD_DIR="${ROOT_DIR}/build/portal"
install -d -m 0750 "$PORTAL_BUILD_DIR"
cat >"$PORTAL_BUILD_DIR/Dockerfile" <<'PORTAL_DOCKERFILE'
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      apache2 libapache2-mod-php php-cli openssh-client \
      snmp snmpd curl procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/snmpd /run/carrier /var/log/carrier-host
COPY apache-carrier.conf /etc/apache2/sites-enabled/carrier.conf
COPY start-portal.sh /usr/local/sbin/start-portal.sh
COPY serial-mib.sh /usr/local/sbin/serial-mib.sh
RUN chmod 0755 /usr/local/sbin/start-portal.sh /usr/local/sbin/serial-mib.sh \
 && a2dissite 000-default \
 && printf '%s\n' 'ServerName dakshinlink-noc.local' \
      >/etc/apache2/conf-available/servername.conf \
 && a2enconf servername
EXPOSE 80/tcp 161/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/start-portal.sh"]
PORTAL_DOCKERFILE
cp "$FILES_DIR/docker/portal/apache-carrier.conf" "$PORTAL_BUILD_DIR/apache-carrier.conf"
cp "$FILES_DIR/docker/portal/serial-mib.sh" "$PORTAL_BUILD_DIR/serial-mib.sh"
cat >"$PORTAL_BUILD_DIR/start-portal.sh" <<'PORTAL_BOOTSTRAP'
#!/usr/bin/env bash
set -Eeuo pipefail
: "${DEVICE_SERIAL:?missing DEVICE_SERIAL}"
: "${R1_MGMT_IP:?missing R1_MGMT_IP}"

install -d -m 0700 -o www-data -g www-data /var/www/.ssh
install -m 0600 -o www-data -g www-data \
  /run/carrier/diag_key /var/www/.ssh/id_ed25519
install -m 0600 -o www-data -g www-data \
  /dev/null /var/www/.ssh/known_hosts
install -d -m 0755 /var/log/carrier-host
rm -rf /var/log/apache2 /var/log/carrier-portal
ln -s /var/log/carrier-host /var/log/apache2
ln -s /var/log/carrier-host /var/log/carrier-portal
touch \
  /var/log/carrier-host/audit.jsonl \
  /var/log/carrier-host/router-keyscan.log \
  /var/log/carrier-host/snmpd.log
chown -R www-data:adm /var/log/carrier-host

(
  for _ in $(seq 1 120); do
    keyscan_tmp="$(mktemp /run/carrier/known-hosts.XXXXXX)"
    if ssh-keyscan -T 3 -H "$R1_MGMT_IP" >"$keyscan_tmp" 2>/dev/null \
      && [[ -s "$keyscan_tmp" ]]; then
      install -m 0600 -o www-data -g www-data \
        "$keyscan_tmp" /var/www/.ssh/known_hosts
      rm -f "$keyscan_tmp"
      exit 0
    fi
    rm -f "$keyscan_tmp"
    sleep 2
  done
  printf '%s router SSH host key could not be collected during startup\n' \
    "$(date -Is)" >>/var/log/carrier-host/router-keyscan.log
) &

cat >/etc/snmp/snmpd.conf <<'EOF'
agentAddress udp:161
sysLocation DakshinLink Network Operations Centre
sysContact noc@dakshinlink.example
rocommunity public
pass .1.3.6.1.2.1.47.1.1.1.1.11 /usr/local/sbin/serial-mib.sh
dontLogTCPWrappersConnects yes
EOF
snmpd -f -Lo -C -c /etc/snmp/snmpd.conf \
  >>/var/log/carrier-host/snmpd.log 2>&1 &
SNMPD_PID="$!"
sleep 1
kill -0 "$SNMPD_PID" >/dev/null 2>&1 \
  || {
    tail -n 100 /var/log/carrier-host/snmpd.log >&2 || true
    exit 1
  }
exec apachectl -D FOREGROUND
PORTAL_BOOTSTRAP
chmod 0755 "$PORTAL_BUILD_DIR/start-portal.sh"

ENDPOINT_BUILD_DIR="${ROOT_DIR}/build/endpoint"
install -d -m 0750 "$ENDPOINT_BUILD_DIR"
cat >"$ENDPOINT_BUILD_DIR/Dockerfile" <<'ENDPOINT_DOCKERFILE'
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      vsftpd curl iproute2 ca-certificates openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /run/vsftpd/empty /var/log/carrier \
 && chmod 0555 /run/vsftpd/empty
COPY start-ftp.sh /usr/local/sbin/start-ftp.sh
COPY start-client.sh /usr/local/sbin/start-client.sh
RUN chmod 0755 /usr/local/sbin/start-ftp.sh /usr/local/sbin/start-client.sh
ENDPOINT_DOCKERFILE
cat >"$ENDPOINT_BUILD_DIR/start-ftp.sh" <<'FTP_BOOTSTRAP'
#!/usr/bin/env bash
set -Eeuo pipefail
: "${FTP_USERNAME:?missing FTP_USERNAME}"
: "${FTP_PASSWORD:?missing FTP_PASSWORD}"
: "${FTP_GATEWAY:?missing FTP_GATEWAY}"
getent passwd "$FTP_USERNAME" >/dev/null 2>&1 \
  || useradd -m -d "/srv/ftp/${FTP_USERNAME}" -s /bin/bash "$FTP_USERNAME"
printf '%s:%s\n' "$FTP_USERNAME" "$FTP_PASSWORD" | chpasswd
home="/srv/ftp/${FTP_USERNAME}"
install -d -m 0750 -o "$FTP_USERNAME" -g "$FTP_USERNAME" "$home/archive"
install -d -m 0555 -o root -g root /run/vsftpd/empty
touch /var/log/carrier/vsftpd.log
chown root:adm /var/log/carrier/vsftpd.log
chmod 0640 /var/log/carrier/vsftpd.log
cat >"$home/archive/network-operations-archive.txt" <<'EOF'
DakshinLink inter-carrier operations archive
Classification: internal network operations data
The archive confirms that the protected FTP workflow remains functional.
EOF
chown "$FTP_USERNAME:$FTP_USERNAME" \
  "$home/archive/network-operations-archive.txt"
mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1
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
xferlog_std_format=NO
vsftpd_log_file=/var/log/carrier/vsftpd.log
log_ftp_protocol=YES
connect_from_port_20=YES
seccomp_sandbox=NO
pam_service_name=vsftpd
secure_chroot_dir=/run/vsftpd/empty
local_root=$home
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30009
EOF
ip route replace default via "$FTP_GATEWAY"
exec /usr/sbin/vsftpd /etc/vsftpd.conf
FTP_BOOTSTRAP
cat >"$ENDPOINT_BUILD_DIR/start-client.sh" <<'CLIENT_BOOTSTRAP'
#!/usr/bin/env bash
set -Eeuo pipefail
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
CLIENT_BOOTSTRAP
chmod 0755 \
  "$ENDPOINT_BUILD_DIR/start-ftp.sh" \
  "$ENDPOINT_BUILD_DIR/start-client.sh"

build_image(){
  local label="$1" image="$2" context="$3"
  local build_log="${RUNTIME_DIR}/build-${label}.log"
  local -a command
  if docker buildx version >/dev/null 2>&1; then
    command=(
      docker buildx build --load --no-cache --progress=plain
      -t "$image" "$context"
    )
  else
    command=(docker build --no-cache -q -t "$image" "$context")
  fi
  if ! "${command[@]}" >"$build_log" 2>&1; then
    printf '[SETUP-BUILD-FAIL] Image build failed for %s\n' "$label" >&2
    tail -n 240 "$build_log" >&2 || true
    fail "Unable to build ${label} image"
  fi
}
build_image router "$ROUTER_IMAGE" "$ROUTER_BUILD_DIR"
build_image portal "$PORTAL_IMAGE" "$PORTAL_BUILD_DIR"
build_image endpoint "$ENDPOINT_IMAGE" "$ENDPOINT_BUILD_DIR"

validate_router_image(){
  local conf="$1" router_role="$2"
  local selftest_ip selftest_log selftest_container
  selftest_ip="$(address "$MGMT_SUBNET" 6)"
  selftest_log="${RUNTIME_DIR}/router-selftest-${router_role}.log"
  selftest_container="carrier-router-selftest-${router_role}-${INSTANCE_ID}"
  docker rm -f "$selftest_container" >/dev/null 2>&1 || true
  if ! timeout --signal=TERM --kill-after=10s 90s \
       docker run --rm \
       --name "$selftest_container" \
       --hostname "router-selftest-${router_role}" \
       --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
       --sysctl net.ipv4.ip_forward=1 \
       --network "$MGMT_NETWORK" --ip "$selftest_ip" \
       -e STARTUP_SELFTEST=1 \
       -v "$conf:/run/carrier/bootstrap-frr.conf:ro" \
       "$ROUTER_IMAGE" >"$selftest_log" 2>&1; then
    docker rm -f "$selftest_container" >/dev/null 2>&1 || true
    printf '[SETUP-SELFTEST-FAIL] Router image/config validation failed for %s\n' \
      "$router_role" >&2
    tail -n 240 "$selftest_log" >&2 || true
    fail "Router runtime self-test failed for ${router_role}"
  fi
}
validate_router_image "$CONFIG_DIR/r1-frr.conf" r1
validate_router_image "$CONFIG_DIR/r2-frr.conf" r2
validate_router_image "$CONFIG_DIR/r3-frr.conf" r3

validate_portal_image(){
  local selftest_container selftest_ip selftest_telemetry
  local http_ready=0 snmp_ready=0
  selftest_container="carrier-portal-selftest-${INSTANCE_ID}"
  selftest_ip="$(address "$MGMT_SUBNET" 5)"
  selftest_telemetry="${RUNTIME_DIR}/portal-selftest"
  rm -rf "$selftest_telemetry"
  install -d -m 0750 "$selftest_telemetry"
  docker rm -f "$selftest_container" >/dev/null 2>&1 || true
  docker run -d \
    --name "$selftest_container" \
    --hostname "portal-selftest-${INSTANCE_ID}" \
    --network "$MGMT_NETWORK" --ip "$selftest_ip" \
    -e "DEVICE_SERIAL=$DEVICE_SERIAL" \
    -e "R1_MGMT_IP=$R1_MGMT_IP" \
    -e "PORTAL_BRAND=$PORTAL_BRAND" \
    -v "$WEBROOT_DIR:/var/www/html:ro" \
    -v "$RUNTIME_DIR/portal_diag_key:/run/carrier/diag_key:ro" \
    -v "$selftest_telemetry:/var/log/carrier-host" \
    "$PORTAL_IMAGE" >/dev/null
  for _ in $(seq 1 45); do
    if docker exec "$selftest_container" \
         curl -fsS --max-time 3 http://127.0.0.1/ \
         >/dev/null 2>&1; then
      http_ready=1
    fi
    if docker exec "$selftest_container" \
         snmpwalk -v1 -c public -t 1 -r 0 \
           udp:127.0.0.1:161 \
           .1.3.6.1.2.1.47.1.1.1.1.11 2>/dev/null \
         | grep -Fq "$DEVICE_SERIAL"; then
      snmp_ready=1
    fi
    if [[ "$http_ready" -eq 1 && "$snmp_ready" -eq 1 ]]; then
      break
    fi
    docker inspect --format '{{.State.Running}}' "$selftest_container" \
      2>/dev/null | grep -Fxq true || break
    sleep 1
  done
  if [[ "$http_ready" -ne 1 || "$snmp_ready" -ne 1 ]]; then
    printf '[SETUP-SELFTEST-FAIL] Portal validation failed: HTTP=%s SNMP=%s\n' \
      "$http_ready" "$snmp_ready" >&2
    printf '%s\n' '[SETUP-DIAGNOSTICS] Internal HTTP probe:' >&2
    docker exec "$selftest_container" \
      curl -v --max-time 5 http://127.0.0.1/ >&2 || true
    printf '%s\n' '[SETUP-DIAGNOSTICS] Internal SNMP probe:' >&2
    docker exec "$selftest_container" \
      snmpwalk -v1 -c public -t 2 -r 1 \
        udp:127.0.0.1:161 \
        .1.3.6.1.2.1.47.1.1.1.1.11 >&2 || true
    printf '%s\n' '[SETUP-DIAGNOSTICS] SNMP service log:' >&2
    tail -n 160 "$selftest_telemetry/snmpd.log" >&2 || true
    docker inspect "$selftest_container" >&2 || true
    docker logs --tail 240 "$selftest_container" >&2 || true
    docker rm -f "$selftest_container" >/dev/null 2>&1 || true
    fail "Portal runtime self-test failed"
  fi
  docker rm -f "$selftest_container" >/dev/null 2>&1 || true
}
validate_portal_image

validate_endpoint_image(){
  local selftest_container selftest_telemetry ready=0
  selftest_container="carrier-ftp-selftest-${INSTANCE_ID}"
  selftest_telemetry="${RUNTIME_DIR}/ftp-selftest"
  rm -rf "$selftest_telemetry"
  install -d -m 0750 "$selftest_telemetry"
  docker rm -f "$selftest_container" >/dev/null 2>&1 || true
  docker run -d \
    --name "$selftest_container" \
    --hostname "ftp-selftest-${INSTANCE_ID}" \
    --cap-add NET_ADMIN \
    --network "$FTP_NETWORK" --ip "$FTP_SERVER_IP" \
    -e "FTP_USERNAME=$FTP_USERNAME" \
    -e "FTP_PASSWORD=$FTP_PASSWORD" \
    -e "FTP_GATEWAY=$R3_FTP_IP" \
    -v "$selftest_telemetry:/var/log/carrier" \
    --entrypoint /usr/local/sbin/start-ftp.sh \
    "$ENDPOINT_IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    if docker run --rm \
         --network "$FTP_NETWORK" \
         --entrypoint curl "$ENDPOINT_IMAGE" \
         -fsS --max-time 8 --ftp-method nocwd \
         --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
         "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt" \
         >/dev/null 2>&1; then
      ready=1
      break
    fi
    docker inspect --format '{{.State.Running}}' "$selftest_container" \
      2>/dev/null | grep -Fxq true || break
    sleep 1
  done
  if [[ "$ready" -ne 1 ]]; then
    printf '%s\n' '[SETUP-SELFTEST-FAIL] FTP validation failed' >&2
    docker inspect "$selftest_container" >&2 || true
    docker logs --tail 200 "$selftest_container" >&2 || true
    printf '%s\n' '[SETUP-DIAGNOSTICS] FTP greeting and transfer:' >&2
    docker run --rm \
      --network "$FTP_NETWORK" \
      --entrypoint curl "$ENDPOINT_IMAGE" \
      -v --max-time 8 --ftp-method nocwd \
      --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
      "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt" \
      -o /dev/null >&2 || true
    printf '%s\n' '[SETUP-DIAGNOSTICS] FTP protocol log:' >&2
    tail -n 160 "$selftest_telemetry/vsftpd.log" >&2 || true
    docker rm -f "$selftest_container" >/dev/null 2>&1 || true
    fail "FTP runtime self-test failed"
  fi
  docker rm -f "$selftest_container" >/dev/null 2>&1 || true
  rm -rf "$selftest_telemetry"
}
validate_endpoint_image

create_router(){
  local name="$1" hostname="$2" conf="$3" telemetry="$4" capture="$5"
  local primary_network="$6" primary_ip="$7"
  docker create --name "$name" --hostname "$hostname" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --sysctl net.ipv4.ip_forward=1 \
    --network "$primary_network" --ip "$primary_ip" \
    -e "CAPTURE_TRANSIT=$capture" \
    -v "$conf:/run/carrier/bootstrap-frr.conf:ro" \
    -v "$telemetry:/var/log/carrier" \
    "$ROUTER_IMAGE" >/dev/null
}
create_router "$R1_CONTAINER" "$R1_HOSTNAME" "$CONFIG_DIR/r1-frr.conf" \
  "$TELEMETRY_DIR/r1" 1 "$MGMT_NETWORK" "$R1_MGMT_IP"
create_router "$R2_CONTAINER" "$R2_HOSTNAME" "$CONFIG_DIR/r2-frr.conf" \
  "$TELEMETRY_DIR/r2" 0 "$R1R2_NETWORK" "$R2_R1R2_IP"
create_router "$R3_CONTAINER" "$R3_HOSTNAME" "$CONFIG_DIR/r3-frr.conf" \
  "$TELEMETRY_DIR/r3" 0 "$R1R3_NETWORK" "$R3_R1R3_IP"
docker cp "$CONFIG_DIR/r1-authorized_keys" "${R1_CONTAINER}:/run/carrier/authorized_keys"

docker network connect --ip "$R1_R1R2_IP" "$R1R2_NETWORK" "$R1_CONTAINER"
docker network connect --ip "$R1_R1R3_IP" "$R1R3_NETWORK" "$R1_CONTAINER"
docker network connect --ip "$R2_R2R3_IP" "$R2R3_NETWORK" "$R2_CONTAINER"
docker network connect --ip "$R2_CLIENT_IP" "$CLIENT_NETWORK" "$R2_CONTAINER"
docker network connect --ip "$R3_R2R3_IP" "$R2R3_NETWORK" "$R3_CONTAINER"
docker network connect --ip "$R3_FTP_IP" "$FTP_NETWORK" "$R3_CONTAINER"

docker create --name "$FTP_CONTAINER" --hostname "archive-${INSTANCE_ID}" \
  --cap-add NET_ADMIN --network "$FTP_NETWORK" --ip "$FTP_SERVER_IP" \
  -e "FTP_USERNAME=$FTP_USERNAME" -e "FTP_PASSWORD=$FTP_PASSWORD" \
  -e "FTP_GATEWAY=$R3_FTP_IP" \
  -v "$TELEMETRY_DIR/ftp:/var/log/carrier" \
  --entrypoint /usr/local/sbin/start-ftp.sh "$ENDPOINT_IMAGE" >/dev/null
docker create --name "$CLIENT_CONTAINER" --hostname "vip-${INSTANCE_ID}" \
  --cap-add NET_ADMIN --network "$CLIENT_NETWORK" --ip "$CLIENT_IP" \
  -e "FTP_USERNAME=$FTP_USERNAME" -e "FTP_PASSWORD=$FTP_PASSWORD" \
  -e "FTP_SERVER_IP=$FTP_SERVER_IP" -e "CLIENT_GATEWAY=$R2_CLIENT_IP" \
  -v "$TELEMETRY_DIR/client:/var/log/carrier" \
  --entrypoint /usr/local/sbin/start-client.sh "$ENDPOINT_IMAGE" >/dev/null
docker create --name "$PORTAL_CONTAINER" --hostname "noc-${INSTANCE_ID}" \
  --network "$MGMT_NETWORK" --ip "$PORTAL_MGMT_IP" \
  -p "${PUBLIC_HTTP_PORT}:80/tcp" -p "${PUBLIC_SNMP_PORT}:161/udp" \
  -e "DEVICE_SERIAL=$DEVICE_SERIAL" -e "R1_MGMT_IP=$R1_MGMT_IP" \
  -e "PORTAL_BRAND=$PORTAL_BRAND" \
  -v "$WEBROOT_DIR:/var/www/html:ro" \
  -v "$RUNTIME_DIR/portal_diag_key:/run/carrier/diag_key:ro" \
  -v "$TELEMETRY_DIR/portal:/var/log/carrier-host" \
  "$PORTAL_IMAGE" >/dev/null

install_unit(){
  local template="$1" target="$2" container="$3"
  sed "s|@@CONTAINER@@|${container}|g" "$template" >"$target"
}
install_unit "$FILES_DIR/systemd/frr.service.template" "/etc/systemd/system/frr.service" "$R1_CONTAINER"
install_unit "$FILES_DIR/systemd/r2.service.template" "/etc/systemd/system/${SLUG}-r2.service" "$R2_CONTAINER"
install_unit "$FILES_DIR/systemd/r3.service.template" "/etc/systemd/system/${SLUG}-r3.service" "$R3_CONTAINER"
install_unit "$FILES_DIR/systemd/portal.service.template" "/etc/systemd/system/${SLUG}-portal.service" "$PORTAL_CONTAINER"
install_unit "$FILES_DIR/systemd/ftp.service.template" "/etc/systemd/system/${SLUG}-ftp.service" "$FTP_CONTAINER"
install_unit "$FILES_DIR/systemd/client.service.template" "/etc/systemd/system/${SLUG}-client.service" "$CLIENT_CONTAINER"

PUBLIC_IF="$(ip -4 route show default | awk 'NR==1{print $5}')"
PUBLIC_IP="$(ip -o -4 address show dev "$PUBLIC_IF" scope global | awk 'NR==1{split($4,a,"/"); print a[1]}')"
[[ -n "$PUBLIC_IF" && -n "$PUBLIC_IP" ]] || fail "Unable to discover participant-facing interface and address"
cat >"$RUNTIME_DIR/scoring.env" <<EOF
SLUG=$SLUG
INSTANCE_ID=$INSTANCE_ID
R1_CONTAINER=$R1_CONTAINER
R2_CONTAINER=$R2_CONTAINER
R3_CONTAINER=$R3_CONTAINER
PORTAL_CONTAINER=$PORTAL_CONTAINER
FTP_CONTAINER=$FTP_CONTAINER
CLIENT_CONTAINER=$CLIENT_CONTAINER
MGMT_NETWORK=$MGMT_NETWORK
R1R2_NETWORK=$R1R2_NETWORK
R1R3_NETWORK=$R1R3_NETWORK
R2R3_NETWORK=$R2R3_NETWORK
CLIENT_NETWORK=$CLIENT_NETWORK
FTP_NETWORK=$FTP_NETWORK
R1_R1R2_IP=$R1_R1R2_IP
R2_R1R2_IP=$R2_R1R2_IP
R1_R1R3_IP=$R1_R1R3_IP
R3_R1R3_IP=$R3_R1R3_IP
R2_R2R3_IP=$R2_R2R3_IP
R3_R2R3_IP=$R3_R2R3_IP
R2_CLIENT_IP=$R2_CLIENT_IP
CLIENT_IP=$CLIENT_IP
R3_FTP_IP=$R3_FTP_IP
FTP_SERVER_IP=$FTP_SERVER_IP
FTP_SUBNET=$FTP_SUBNET
HIJACK_PREFIX_A=$HIJACK_PREFIX_A
HIJACK_PREFIX_B=$HIJACK_PREFIX_B
AS1=$AS1
AS2=$AS2
AS3=$AS3
FTP_USERNAME=$FTP_USERNAME
FTP_PASSWORD=$FTP_PASSWORD
PUBLIC_IP=$PUBLIC_IP
PUBLIC_HTTP_PORT=$PUBLIC_HTTP_PORT
PUBLIC_SNMP_PORT=$PUBLIC_SNMP_PORT
TELEMETRY_DIR=$TELEMETRY_DIR
EOF
cat >"$RUNTIME_DIR/operator.env" <<EOF
PUBLIC_IF=$PUBLIC_IF
PUBLIC_IP=$PUBLIC_IP
PUBLIC_HTTP_PORT=$PUBLIC_HTTP_PORT
PUBLIC_SNMP_PORT=$PUBLIC_SNMP_PORT
PORTAL_USERNAME=admin
DEVICE_SERIAL=$DEVICE_SERIAL
PORTAL_BRAND=$PORTAL_BRAND
ORG1=$ORG1
ORG2=$ORG2
ORG3=$ORG3
R1_HOSTNAME=$R1_HOSTNAME
R2_HOSTNAME=$R2_HOSTNAME
R3_HOSTNAME=$R3_HOSTNAME
EOF
cat >"$RUNTIME_DIR/assessment-answers.env" <<EOF
AS1=$AS1
FTP_PASSWORD=$FTP_PASSWORD
HIJACK_PREFIX_A=$HIJACK_PREFIX_A
HIJACK_PREFIX_B=$HIJACK_PREFIX_B
EOF
chmod 0600 "$RUNTIME_DIR/scoring.env" "$RUNTIME_DIR/operator.env" \
  "$RUNTIME_DIR/assessment-answers.env"

systemctl daemon-reload
systemctl reset-failed \
  frr.service \
  "${SLUG}-r2.service" "${SLUG}-r3.service" \
  "${SLUG}-portal.service" "${SLUG}-ftp.service" \
  "${SLUG}-client.service" >/dev/null 2>&1 || true
systemctl enable --now \
  "${SLUG}-r2.service" "${SLUG}-r3.service" frr.service \
  "${SLUG}-ftp.service" "${SLUG}-client.service" "${SLUG}-portal.service"

dump_startup_diagnostics(){
  local container
  printf '%s\n' '[SETUP-DIAGNOSTICS] Service startup state follows:' >&2
  systemctl --no-pager --full status \
    frr.service "${SLUG}-r2.service" "${SLUG}-r3.service" \
    "${SLUG}-portal.service" "${SLUG}-ftp.service" \
    "${SLUG}-client.service" >&2 || true
  for container in \
    "$R1_CONTAINER" "$R2_CONTAINER" "$R3_CONTAINER" \
    "$PORTAL_CONTAINER" "$FTP_CONTAINER" "$CLIENT_CONTAINER"; do
    printf '[SETUP-DIAGNOSTICS] %s: ' "$container" >&2
    docker inspect --format \
      'status={{.State.Status}} running={{.State.Running}} restarting={{.State.Restarting}} exit={{.State.ExitCode}} restarts={{.RestartCount}} error={{.State.Error}}' \
      "$container" >&2 || true
    docker logs --tail 200 "$container" >&2 || true
  done
  for container in "$R1_CONTAINER" "$R2_CONTAINER" "$R3_CONTAINER"; do
    printf '[SETUP-DIAGNOSTICS] %s BGP summary:\n' "$container" >&2
    docker exec "$container" \
      vtysh -c 'show bgp ipv4 unicast summary' >&2 || true
    printf '[SETUP-DIAGNOSTICS] %s IPv4 routes:\n' "$container" >&2
    docker exec "$container" \
      vtysh -c 'show ip route' >&2 || true
  done
  printf '%s\n' '[SETUP-DIAGNOSTICS] Authenticated FTP greeting and transfer:' >&2
  docker exec "$CLIENT_CONTAINER" \
    curl -v --max-time 12 --ftp-method nocwd \
      --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
      "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt" \
      -o /dev/null >&2 || true
  printf '%s\n' '[SETUP-DIAGNOSTICS] FTP protocol log:' >&2
  tail -n 160 "$TELEMETRY_DIR/ftp/vsftpd.log" >&2 || true
}

wait_until(){
  local subject="$1"
  shift
  for _ in $(seq 1 45); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 2
  done
  dump_startup_diagnostics
  fail "Timed out waiting for ${subject}"
}
r1_bgp_port_ready(){
  docker exec "$R1_CONTAINER" ss -lntH \
    | awk '{print $4}' | grep -Eq '(^|:)179$'
}
r1_peers_ready(){
  local summary_json summary_text

  # FRR 8.x patch releases do not all expose the same filtered-summary JSON
  # command or identical peer-state key. Query the complete summary and accept
  # every known state key only when both expected peers say Established.
  if summary_json="$(
       docker exec "$R1_CONTAINER" \
         vtysh -c 'show bgp ipv4 unicast summary json' 2>/dev/null
     )" \
     && jq -e \
          --arg r2 "$R2_R1R2_IP" \
          --arg r3 "$R3_R1R3_IP" '
            (.ipv4Unicast.peers // .peers // {}) as $peers
            | def established($peer):
                ($peers[$peer] // {}) as $entry
                | (($entry.state // $entry.bgpState // $entry.peerState // "")
                    == "Established");
            established($r2) and established($r3)
          ' <<<"$summary_json" >/dev/null 2>&1; then
    return 0
  fi

  # In the stable human summary, column 10 is numeric only for an
  # Established peer; every non-established state is rendered as text there.
  summary_text="$(
    docker exec "$R1_CONTAINER" \
      vtysh -c 'show bgp ipv4 unicast summary' 2>/dev/null
  )" || return 1
  awk -v peer="$R2_R1R2_IP" \
    '$1 == peer && $10 ~ /^[0-9]+$/ { found=1 } END { exit(found ? 0 : 1) }' \
    <<<"$summary_text" \
    && awk -v peer="$R3_R1R3_IP" \
      '$1 == peer && $10 ~ /^[0-9]+$/ { found=1 } END { exit(found ? 0 : 1) }' \
      <<<"$summary_text"
}
portal_http_ready(){
  curl -fsS --max-time 4 "http://127.0.0.1:${PUBLIC_HTTP_PORT}/"
}
portal_snmp_ready(){
  snmpwalk -v1 -c public -t 2 -r 1 \
    "udp:127.0.0.1:${PUBLIC_SNMP_PORT}" \
    .1.3.6.1.2.1.47.1.1.1.1.11 | grep -F "$DEVICE_SERIAL"
}
ftp_workflow_ready(){
  docker exec "$CLIENT_CONTAINER" \
    curl -fsS --max-time 12 --ftp-method nocwd \
      --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
      "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt"
}
wait_until "R1 BGP port" r1_bgp_port_ready
wait_until "R1 peers" r1_peers_ready
wait_until "portal HTTP" portal_http_ready
wait_until "serial SNMP" portal_snmp_ready
wait_until "FTP workflow" ftp_workflow_ready
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP" | grep -Fq "via $R3_R2R3_IP" \
  || fail "Baseline FTP path is not direct from AS2 to AS3"

log "Operator runtime state: $RUNTIME_DIR"
log "Live telemetry: $TELEMETRY_DIR"
echo "Setup Successfully"
