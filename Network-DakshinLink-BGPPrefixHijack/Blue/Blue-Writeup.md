# solve_blue.md - NWR-CARRIER-01 - DakshinLink Route Interception
## Blue Team Detection, Containment and Remediation

**Component:** DakshinLink management portal and three-AS FRRouting topology  
**Primary availability:** `frr.service` plus TCP/179 inside the active edge router  
**Attack chain:** SNMP disclosure -> default credential use -> authenticated diagnostic command injection -> root router shell -> selective more-specific BGP hijack -> FTP credential interception  
**MITRE ATT&CK:** T1046, T1190, T1059, T1016, T1557

---

## 1. Understand the baseline

Become root on the Blue challenge VM and load the generated operator state:

```bash
sudo -i
export BASE=/opt/network-challenges/carrier-dakshinlink-route-interception
source "$BASE/runtime/scoring.env"
source "$BASE/runtime/operator.env"
```

These files are mode `0600` and exist for operators and defenders. Red
participants must discover the same network values from live services.

Validate the two primary vectors:

```bash
systemctl is-active frr.service
docker exec "$R1_CONTAINER" ss -lntp | grep ':179 '
```

Validate the clean custom state:

```bash
docker exec "$R1_CONTAINER" vtysh -c "show bgp ipv4 unicast summary"
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP"
docker exec "$CLIENT_CONTAINER" \
  curl -fsS --max-time 12 --ftp-method nocwd \
  --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
  "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt"
```

Normal state:

- R1 has established sessions with the generated R2 and R3 neighbor IPs.
- R2 reaches the protected FTP host directly through `$R3_R2R3_IP`.
- R1 does not originate `$HIJACK_PREFIX_A` or `$HIJACK_PREFIX_B`.
- No long-running root SSH command session exists on R1.
- The real FTP transaction succeeds.

## 2. Real evidence locations

No scenario telemetry is pre-generated. Every record below is produced by
the running service or the participant's actual traffic:

| Evidence | Location |
|---|---|
| Apache access and error logs | `$BASE/telemetry/portal/access.log`, `error.log` |
| Portal security audit | `$BASE/telemetry/portal/audit.jsonl` |
| Net-SNMP process log | `$BASE/telemetry/portal/snmpd.log` |
| R1 SSH authentication log | `$BASE/telemetry/r1/auth.log` |
| R1 FRRouting log | `$BASE/telemetry/r1/frr.log` |
| R1 transit PCAP | `$BASE/telemetry/r1/transit.pcap` |
| R2/R3 FRRouting logs | `$BASE/telemetry/r2/frr.log`, `$BASE/telemetry/r3/frr.log` |
| Real FTP protocol log | `$BASE/telemetry/ftp/vsftpd.log` |
| Protected-host SSH log | `$BASE/telemetry/ftp/ssh.log` |
| Scheduled client result | `$BASE/telemetry/client/client-transfer.jsonl` |

## 3. Detection - reconstruct the intrusion

### 3.1 Identify the external source

```bash
tail -n 100 "$BASE/telemetry/portal/access.log"
jq -c '.' "$BASE/telemetry/portal/audit.jsonl" | tail -n 100
```

Hunt for this sequence from the same source:

1. Requests to `/doc/` or `/debug/`
2. Successful `POST /index.php`
3. `POST /diag.php`
4. An audit event where `action=diagnostic_execute` and the decoded value
   contains a command separator or shell syntax

Query only diagnostic execution:

```bash
jq -r '
  select(.action=="diagnostic_execute") |
  [.timestamp,.source_ip,.session_user,.decoded_check] | @tsv
' "$BASE/telemetry/portal/audit.jsonl"
```

The `source_ip` is the real corresponding Red participant in Red-vs-Blue,
not a configured exercise placeholder.

### 3.2 Confirm root execution on the router

```bash
tail -n 100 "$BASE/telemetry/r1/auth.log"
docker exec "$R1_CONTAINER" ps -eo pid,ppid,etimes,user,args --forest
docker exec "$R1_CONTAINER" ss -ntp
```

Indicators:

- A root public-key SSH session from the portal management address
- `sshd: root@notty` lasting longer than a normal diagnostic request
- Shell processes such as `bash -i`, `/dev/tcp`, `mkfifo`, `nc` or `socat`
- An outbound established TCP session from R1 to an external callback

### 3.3 Confirm BGP control-plane manipulation

```bash
docker exec "$R1_CONTAINER" vtysh -c "show running-config"
docker exec "$R1_CONTAINER" vtysh -c "show bgp ipv4 unicast summary"
docker exec "$R1_CONTAINER" \
  vtysh -c "show bgp ipv4 unicast neighbors $R2_R1R2_IP advertised-routes"
docker exec "$R1_CONTAINER" \
  vtysh -c "show bgp ipv4 unicast neighbors $R3_R1R3_IP advertised-routes"
grep -Ei 'ADJCHANGE|Update|prefix|route' "$BASE/telemetry/r1/frr.log" | tail -n 100
```

High-confidence malicious state:

- R1 originates `$HIJACK_PREFIX_A` or `$HIJACK_PREFIX_B`.
- Route-map `TO-AS2` applies `community no-export` to `HIJACK`.
- Route-map `TO-AS3` denies `HIJACK`.
- R2's selected route to `$FTP_SERVER_IP` changes from
  `$R3_R2R3_IP` to `$R1_R1R2_IP`.

Verify the data-plane change:

```bash
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP"
```

### 3.4 Confirm credential interception from packets

```bash
tcpdump -nn -r "$BASE/telemetry/r1/transit.pcap" \
  "tcp port 21 or tcp port 179 or tcp port 22"
tcpdump -A -nn -r "$BASE/telemetry/r1/transit.pcap" \
  "dst host $FTP_SERVER_IP and tcp dst port 21"
```

If FTP `USER` and `PASS` commands appear on R1, the route interception
changed real traffic flow. Compare timestamps with:

```bash
tail -n 100 "$BASE/telemetry/ftp/vsftpd.log"
tail -n 100 "$BASE/telemetry/client/client-transfer.jsonl"
```

## 4. Detection queries

### 4.1 Shell query for injected diagnostics

```bash
jq -r '
  select(.action=="diagnostic_execute") |
  select(.decoded_check | test("[;&|`]|\\$\\(|/dev/tcp|base64"; "i")) |
  [.timestamp,.source_ip,.decoded_check] | @tsv
' "$BASE/telemetry/portal/audit.jsonl"
```

### 4.2 Splunk examples

```spl
index=network source="/opt/network-challenges/carrier-dakshinlink-route-interception/telemetry/portal/audit.jsonl"
action=diagnostic_execute
| regex decoded_check="[;&|`]|/dev/tcp|base64"
| table _time source_ip session_user decoded_check
```

```spl
index=network source="*/telemetry/r1/frr.log"
("ADJCHANGE" OR "Update" OR "prefix")
| transaction host maxspan=10m
| table _time host _raw
```

### 4.3 Wazuh collection

Add the real files to the agent configuration:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/network-challenges/carrier-dakshinlink-route-interception/telemetry/portal/audit.jsonl</location>
</localfile>
<localfile>
  <log_format>apache</log_format>
  <location>/opt/network-challenges/carrier-dakshinlink-route-interception/telemetry/portal/access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/network-challenges/carrier-dakshinlink-route-interception/telemetry/r1/frr.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/network-challenges/carrier-dakshinlink-route-interception/telemetry/r1/auth.log</location>
</localfile>
```

Validate the Wazuh configuration before restarting the agent.

## 5. Immediate containment

### 5.1 Preserve evidence first

```bash
export CASE="/tmp/carrier-case-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$CASE"
cp -a "$BASE/telemetry/portal" "$CASE/"
cp -a "$BASE/telemetry/r1" "$CASE/"
docker exec "$R1_CONTAINER" vtysh -c "show running-config" >"$CASE/r1-running-config.txt"
docker exec "$R1_CONTAINER" vtysh -c "show bgp ipv4 unicast" >"$CASE/r1-bgp.txt"
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP" >"$CASE/r2-path.txt"
sha256sum "$CASE"/* "$CASE"/*/* >"$CASE/SHA256SUMS.txt" 2>/dev/null || true
```

### 5.2 Block only the confirmed source

Obtain the source from the audit record, then constrain that source at the
Docker ingress chain:

```bash
export ATTACKER_IP="<source-ip-from-live-audit>"
iptables -I DOCKER-USER 1 -s "$ATTACKER_IP" -p tcp \
  --dport "$PUBLIC_HTTP_PORT" -j DROP
```

Do not stop `frr.service`, shut down the portal, or block all BGP traffic.

### 5.3 End the active router shell

Review before terminating:

```bash
docker exec "$R1_CONTAINER" ps -eo pid,ppid,etimes,user,args --forest
docker exec "$R1_CONTAINER" ss -ntp
```

Kill only the confirmed injected shell process or its long-running
`sshd: root@notty` parent. Do not kill `sshd` globally.

### 5.4 Withdraw malicious routes without dropping legitimate peers

```bash
docker exec "$R1_CONTAINER" vtysh \
  -c "configure terminal" \
  -c "router bgp $AS1" \
  -c "no network $HIJACK_PREFIX_A" \
  -c "no network $HIJACK_PREFIX_B" \
  -c "exit" \
  -c "no route-map TO-AS2 permit 10" \
  -c "no route-map TO-AS3 deny 10" \
  -c "no ip prefix-list HIJACK" \
  -c "end" \
  -c "clear bgp $R2_R1R2_IP soft out"
```

Confirm direct routing returns:

```bash
sleep 10
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP"
```

## 6. Eradication and hardening

### 6.1 Remove the command-injection primitive

The vulnerable code concatenates decoded user input into a remote shell
command. Replace it with:

- A fixed server-side diagnostic allowlist
- No client-controlled shell fragment
- `proc_open` argument arrays with a fixed remote command
- A non-root, forced-command SSH key if remote access must remain

A safe diagnostic request should map a user choice such as `routing_status`
to a constant command such as:

```text
vtysh -c "show bgp ipv4 unicast summary"
```

It must never append the decoded value to `ps`, `grep`, `sh`, `bash` or SSH.

### 6.2 Remove default credential derivation

- Rotate the portal administrator password to an independently generated secret.
- Do not derive authentication from the SNMP chassis serial.
- Restrict SNMP to a Blue-approved management network.
- Replace the default `public` community and prefer SNMPv3 authentication/privacy.

### 6.3 Restrict router management

- Replace the portal's unrestricted root key with a forced command.
- Permit SSH only from the management portal address.
- Log all authorised diagnostic invocations.
- Review and rotate the generated key after the incident.

### 6.4 Add BGP route controls

- Permit only owned prefixes from each external peer.
- Apply maximum-prefix limits.
- Reject unexpected more-specific advertisements.
- Monitor origin, AS path, well-known communities and RIB/FIB changes.
- Preserve the legitimate AS2-AS3 path; do not over-harden by shutting BGP down.

## 7. Recovery and service-availability proof

```bash
systemctl is-active frr.service
docker exec "$R1_CONTAINER" ss -lntH |
  awk '{print $4}' | grep -Eq '(^|:)179$'
docker exec "$R1_CONTAINER" vtysh -c "show bgp ipv4 unicast summary"
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP"
docker exec "$CLIENT_CONTAINER" \
  curl -fsS --max-time 12 --ftp-method nocwd \
  --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
  "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt"
```

Recovery is complete only when:

- `frr.service` is active.
- TCP/179 is listening in R1.
- Both legitimate R1 peers are established.
- R2 uses the direct R3 next hop for the FTP server.
- No hijack prefixes or active injected shell remain.
- Portal and real FTP workflow remain functional.

The availability probe is current-state based. It returns to UP after the
malicious route and active shell are removed and legitimate delivery is
restored; it does not remain permanently latched because an attack occurred.
The expected clean result begins with `SERVICE_STATUS:UP`; any failed vector
returns `SERVICE_STATUS:DOWN` and exit code 1.

## 8. Lessons learned

- SNMP inventory data can become authentication material when systems reuse identifiers.
- An authenticated diagnostic feature is still a public attack surface when default credentials are recoverable.
- Root command execution on a router is a control-plane compromise, not merely a web incident.
- BGP control-plane evidence and packet-path evidence must be investigated together.
- Safe containment preserves legitimate routing and the protected workflow.
