# solve_blue.md - NWR-CARRIER-01 - DakshinLink Route Interception
## Blue Team Detection, Containment, Remediation and RPKI Hardening

**Component:** DakshinLink management portal and three-AS FRRouting topology
**Primary availability:** `frr.service` plus TCP/179 inside the active edge router
**Attack chain:** SNMP disclosure -> default credential use -> authenticated diagnostic command injection -> root router shell -> selective more-specific BGP hijack -> FTP credential interception
**MITRE ATT&CK:** T1046, T1190, T1059, T1016, T1557
**Preventive control added in this revision:** RPKI Route Origin Validation (RFC 6811) with a local validator/cache and SLURM local exceptions (RFC 8416)

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
- Deploy RPKI Route Origin Validation as described in section 9. This is the
  control that would have made the hijack fail on arrival rather than after
  detection.

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
- Containment removed the hijack after it succeeded. Origin validation prevents
  the same advertisement from ever being selected. Both are required.

---

# 9. Preventive control - RPKI origin validation on FRRouting

> **Scope of this appendix.** Sections 1-8 are incident response: they detect and
> undo a hijack that already worked. This section builds the control that makes
> the identical attack a no-op even with a fully compromised R1. A defender who
> completes this section should be able to hand a red participant root on R1 and
> still watch the `/25` advertisements be rejected by R2.

## 9.1 Why RPKI stops this specific attack

Recall the exact mechanism the red side used:

| Step | What R1 announced | Why R2 believed it |
|---|---|---|
| Legitimate | R3 (AS3) originates `10.117.117.0/24` | Correct origin, correct prefix |
| Hijack | R1 (AS1) originates `10.117.117.0/25` and `10.117.117.128/25` | Nothing in plain BGP proves AS1 does **not** own that space |

Plain BGP has no notion of ownership. Longest-prefix match then guarantees the
attacker wins: a `/25` beats a `/24` regardless of AS path length, local
preference, or MED. Filtering by path attributes cannot fix this, because the
attacker's path is short and its attributes are legal.

RPKI Route Origin Validation attacks the problem at the correct layer. A **Route
Origin Authorisation (ROA)** is a cryptographically signed statement by the
address-space holder:

```text
prefix        10.117.117.0/24
origin ASN    AS3   (Sahyadri Data Exchange, $AS3)
maxLength     24
```

Every BGP announcement is then given a validation state (RFC 6811):

| State | Meaning in this topology |
|---|---|
| **Valid** | Prefix covered by a ROA, origin ASN matches, length <= maxLength. R3's `/24` from AS3. |
| **Invalid** | Prefix covered by a ROA but origin ASN is wrong **or** the prefix is longer than maxLength. R1's `/25`s from AS1 — wrong origin **and** over maxLength. |
| **NotFound** | No ROA covers the prefix. Everything else in the lab until you sign it. |

Because `maxLength` is pinned at `24`, the hijack is Invalid on two independent
grounds. Even if the attacker somehow spoofed the origin AS to `$AS3`, the
`/25` still exceeds maxLength and is still Invalid. **This is why maxLength must
equal the prefix length you actually announce — a lazy `maxLength 32` would let
the sub-prefix hijack straight through with a forged origin.**

### Where enforcement must live

RPKI is enforced by the **receiver** of an announcement, not the sender.

```text
        [R1 / AS1 - COMPROMISED]
             |            \
   announces /25s          \ announces /25s
             |              \
      [R2 / AS2]            [R3 / AS3]
   <-- MUST VALIDATE -->  <-- MUST VALIDATE -->
```

- **R2 is the critical enforcement point.** R2 is the router the attacker needs
  to fool. If R2 drops Invalid routes, the traffic never leaves AS2 toward R1
  and the FTP session is never intercepted.
- **R3 must also validate**, so a future attacker cannot poison the server side.
- **R1 validates too**, both for its own protection and so that a partially
  compromised R1 with intact configuration cannot be used to launder routes.

Configure all three. Prioritise R2.

## 9.2 Architecture of the local validator/cache

You do not put cryptography on the router. The router is a dumb consumer of a
validated prefix list delivered over the **RTR protocol** (RFC 8210).

```text
  Trust Anchors (RIR TALs)  ------.
                                   \
  SLURM local exceptions (lab)  ----+--->  [ VALIDATOR / CACHE ]
                                              Routinator 3000
                                              (or rpki-client + StayRTR,
                                               FORT, OctoRPKI)
                                                     |
                                          RTR / TCP 3323 (mgmt VRF)
                                                     |
                    +--------------------+-----------+----------+
                    |                    |                      |
              [ R1 bgpd -M rpki ]  [ R2 bgpd -M rpki ]  [ R3 bgpd -M rpki ]
                    |                    |                      |
              route-map RPKI-IN    route-map RPKI-IN     route-map RPKI-IN
```

Design rules for the cache:

1. Run **at least two** validators in production and give the router two `rpki
   cache` entries with different preferences. A single cache is a single point
   of failure for your routing policy.
2. Place the cache on the **management network**, reachable without depending on
   the routes it is validating. A cache reachable only over the data plane will
   deadlock during exactly the incident it exists to prevent.
3. The RTR session is unauthenticated by default. Bind it to the management
   interface, restrict it with firewall rules, and use SSH transport or TCP-AO
   if your validator supports it.
4. The cache must **never** be reachable from the portal container or any host
   the portal can execute commands on. A compromised cache lets an attacker
   assert their own ROAs.

## 9.3 Deploy the validator - Routinator

Routinator is the reference choice: single binary, built-in RTR server, built-in
HTTP status and metrics, native SLURM support.

### 9.3.1 Container deployment (matches the lab's Docker topology)

```bash
# Dedicated management-side network for RPKI, isolated from the AS transit nets
docker network create --subnet 172.31.250.0/24 rpki-mgmt

mkdir -p /opt/rpki/{tals,repository,slurm}
chown -R 1012:1012 /opt/rpki      # routinator runs unprivileged

# Fetch the RIR trust anchor locators once (accepts the ARIN RPA)
docker run --rm -v /opt/rpki/tals:/home/routinator/.rpki-cache/tals \
  nlnetlabs/routinator init --accept-arin-rpa

docker run -d --name rpki-validator \
  --network rpki-mgmt --ip 172.31.250.10 \
  --restart unless-stopped \
  -v /opt/rpki:/home/routinator/.rpki-cache \
  -v /opt/rpki/slurm:/etc/routinator/slurm:ro \
  -p 127.0.0.1:8323:8323 \
  nlnetlabs/routinator server \
    --rtr 0.0.0.0:3323 \
    --http 0.0.0.0:8323 \
    --refresh 600 \
    --rrdp-timeout 30 \
    --exceptions /etc/routinator/slurm/dakshinlink.slurm.json

# Attach the routers to the management network
for C in "$R1_CONTAINER" "$R2_CONTAINER" "$R3_CONTAINER"; do
  docker network connect rpki-mgmt "$C"
done
```

### 9.3.2 Bare-metal / systemd deployment

```bash
apt-get install -y routinator
routinator init --accept-arin-rpa
```

`/etc/routinator/routinator.conf`:

```toml
repository-dir  = "/var/lib/routinator/rpki-cache"
exceptions      = ["/etc/routinator/slurm/dakshinlink.slurm.json"]
refresh         = 600
retry           = 600
expire          = 7200
rtr-listen      = ["172.31.250.10:3323"]
http-listen     = ["127.0.0.1:8323"]
log-level       = "info"
log             = "syslog"
syslog-facility = "daemon"
```

```bash
systemctl enable --now routinator
systemctl is-active routinator
```

### 9.3.3 Alternative - rpki-client + StayRTR

If you prefer the OpenBSD validator with a separate RTR daemon:

```bash
apt-get install -y rpki-client stayrtr

# Validate on a schedule, emit JSON for the RTR daemon
cat >/etc/cron.d/rpki-client <<'EOF'
*/15 * * * * root /usr/sbin/rpki-client -j -o /var/lib/rpki-client/json >/dev/null 2>&1
EOF

# StayRTR serves that JSON over RTR
stayrtr -cache /var/lib/rpki-client/json/rpki.json \
        -bind 172.31.250.10:3323 \
        -checktime=true
```

SLURM is applied by `rpki-client` with `-x /etc/rpki/slurm.json` in this model.

## 9.4 SLURM - making RPKI work with the lab's private ASNs

**This is the step most people miss.** The scenario uses RFC 1918 space
(`10.117.117.0/24`) and private ASNs (`AS64592`, `AS65508`, `AS64655`). No RIR
has ever signed a ROA for any of it, so every prefix in the topology validates as
**NotFound** and RPKI does nothing at all.

RFC 8416 **SLURM** (Simplified Local Internet Number Resource Management) is the
supported mechanism for injecting locally-asserted ROAs into a validator. Real
carriers use it for internal space, private interconnects, and to override a
broken upstream ROA during an outage.

Generate the file from your live operator environment so it tracks the
runtime-generated ASNs:

```bash
mkdir -p /opt/rpki/slurm
python3 - >/opt/rpki/slurm/dakshinlink.slurm.json <<'PY'
import json, os

as1 = int(os.environ["AS1"])   # DakshinLink
as2 = int(os.environ["AS2"])   # Vindhya Broadband
as3 = int(os.environ["AS3"])   # Sahyadri Data Exchange

slurm = {
  "slurmVersion": 1,
  "validationOutputFilters": {
    "prefixFilters": [],
    "bgpsecFilters": []
  },
  "locallyAddedAssertions": {
    "prefixAssertions": [
      {
        "asn": as3,
        "prefix": "10.117.117.0/24",
        "maxPrefixLength": 24,
        "comment": "Sahyadri Data Exchange - protected FTP archive subnet. "
                   "maxLength pinned to 24: any more-specific is Invalid."
      },
      {
        "asn": as2,
        "prefix": "10.195.138.0/24",
        "maxPrefixLength": 24,
        "comment": "Vindhya Broadband - client-side subnet"
      },
      {
        "asn": as1,
        "prefix": "10.187.52.0/24",
        "maxPrefixLength": 24,
        "comment": "DakshinLink - own address space"
      }
    ],
    "bgpsecAssertions": []
  }
}
print(json.dumps(slurm, indent=2))
PY

python3 -c 'import json,sys; json.load(open("/opt/rpki/slurm/dakshinlink.slurm.json"))' \
  && echo "[+] SLURM file is valid JSON"
```

> Replace the three `/24`s with the actual subnets from
> `show bgp ipv4 unicast` on a clean router. Confirm them against
> `$BASE/runtime/operator.env` before signing them into the validator — an
> incorrect assertion here will blackhole legitimate traffic.

Reload and confirm the assertions are live:

```bash
docker restart rpki-validator      # or: systemctl reload routinator
sleep 45

# Local HTTP API - confirm the assertion is present
curl -s http://127.0.0.1:8323/json | \
  jq '.roas[] | select(.prefix|startswith("10.117.117."))'
```

Expected:

```json
{
  "asn": "AS64655",
  "prefix": "10.117.117.0/24",
  "maxLength": 24,
  "ta": "slurm"
}
```

Other useful validator endpoints:

```bash
curl -s http://127.0.0.1:8323/status     # object counts, per-TAL freshness
curl -s http://127.0.0.1:8323/metrics    # Prometheus scrape target
curl -s "http://127.0.0.1:8323/api/v1/validity/AS64592/10.117.117.0/25"
# -> expect "state": "invalid", "reason": "as" / covered by a shorter maxLength
```

That last query is the single best pre-flight test: it asks the validator
directly what it thinks of the exact hijack advertisement, before any router is
touched.

## 9.5 Enable the RPKI module in FRRouting

FRR's `bgpd` only speaks RTR when it is started with the `rpki` module, which
links against `librtr` (rtrlib). Confirm the build has it:

```bash
docker exec "$R1_CONTAINER" bgpd -v
docker exec "$R1_CONTAINER" ls /usr/lib/frr/modules/ | grep -i rpki
# expect: bgpd_rpki.so
```

If `bgpd_rpki.so` is absent the FRR package was built without rtrlib. Install
`frr-rpki-rtrlib` (Debian/Ubuntu ships this as a separate package) or rebuild
with `--enable-rpki`.

Enable the module on **each** router:

```bash
for C in "$R1_CONTAINER" "$R2_CONTAINER" "$R3_CONTAINER"; do
  docker exec "$C" sh -c \
    'sed -i "s|^bgpd_options=.*|bgpd_options=\"  --daemon -A 127.0.0.1 -M rpki\"|" /etc/frr/daemons'
  docker exec "$C" sh -c 'grep ^bgpd_options /etc/frr/daemons'
done
```

Restarting `bgpd` bounces BGP sessions. Do it inside a change window, one router
at a time, and verify adjacencies come back before touching the next:

```bash
docker exec "$R2_CONTAINER" /usr/lib/frr/frr-reload.sh --reload /etc/frr/frr.conf \
  || docker exec "$R2_CONTAINER" systemctl restart frr
sleep 20
docker exec "$R2_CONTAINER" vtysh -c "show bgp ipv4 unicast summary"
```

## 9.6 Configure the RPKI cache connection

On R1, R2 and R3:

```bash
docker exec "$R2_CONTAINER" vtysh \
  -c "configure terminal" \
  -c "rpki" \
  -c "  rpki polling_period 300" \
  -c "  rpki expire_interval 7200" \
  -c "  rpki retry_interval 600" \
  -c "  rpki cache 172.31.250.10 3323 preference 1" \
  -c "  rpki cache 172.31.250.11 3323 preference 2" \
  -c "exit" \
  -c "end" \
  -c "write memory"
```

Equivalent `frr.conf` stanza:

```text
!
rpki
 rpki polling_period 300
 rpki expire_interval 7200
 rpki retry_interval 600
 rpki cache 172.31.250.10 3323 preference 1
 rpki cache 172.31.250.11 3323 preference 2
exit
!
```

Notes on the timers:

- `polling_period` — how often the router asks the cache for a serial update.
  300s is a sane default; lower values increase cache load with little benefit.
- `expire_interval` — how long the router keeps using cached data after the
  cache becomes unreachable. When it expires, **every prefix reverts to
  NotFound**, so your policy must fail open (see 9.7).
- `retry_interval` — reconnection backoff after a failed RTR connection.

Verify the session and the received prefix table:

```bash
docker exec "$R2_CONTAINER" vtysh -c "show rpki cache-connection"
docker exec "$R2_CONTAINER" vtysh -c "show rpki cache-server"
docker exec "$R2_CONTAINER" vtysh -c "show rpki prefix-table"
docker exec "$R2_CONTAINER" vtysh -c "show rpki prefix 10.117.117.0/24"
```

A healthy `show rpki cache-connection` reports the cache as **connected** with a
non-zero serial. If it shows `Connecting` indefinitely, check in order: the
module is loaded, the container is on `rpki-mgmt`, TCP/3323 reachable
(`nc -vz 172.31.250.10 3323`), and validator logs.

## 9.7 Enforcement route-map - the actual control

The RPKI state is exposed to policy through `match rpki {valid|invalid|notfound}`.
Nothing is enforced until you write and apply this route-map.

```text
!
! ---- RPKI Route Origin Validation, inbound from external peers ----
!
route-map RPKI-IN deny 10
 description Drop RPKI Invalid - wrong origin AS or over maxLength
 match rpki invalid
!
route-map RPKI-IN permit 20
 description Unsigned space - accept but never prefer
 match rpki notfound
 set local-preference 90
 set community 65535:0 additive
!
route-map RPKI-IN permit 30
 description Cryptographically valid origin - prefer
 match rpki valid
 set local-preference 120
!
route-map RPKI-IN permit 99
 description Catch-all
!
```

Apply it inbound on every **external** neighbor. On R2 — the router the attacker
is trying to fool — this is the line that defeats the entire attack chain:

```bash
docker exec "$R2_CONTAINER" vtysh \
  -c "configure terminal" \
  -c "router bgp $AS2" \
  -c " address-family ipv4 unicast" \
  -c "  neighbor $R1_R1R2_IP route-map RPKI-IN in" \
  -c "  neighbor $R3_R2R3_IP route-map RPKI-IN in" \
  -c " exit-address-family" \
  -c "end" \
  -c "write memory"

docker exec "$R2_CONTAINER" vtysh -c "clear bgp $R1_R1R2_IP soft in"
docker exec "$R2_CONTAINER" vtysh -c "clear bgp $R3_R2R3_IP soft in"
```

Repeat on R1 (peers `$R2_R1R2_IP`, `$R3_R1R3_IP`) and R3 (peers `$R1_R1R3_IP`,
`$R2_R2R3_IP`).

### Drop versus depref — choose deliberately

| Policy | Behaviour | When to use |
|---|---|---|
| `deny` on Invalid | Route never enters the RIB | Default. Correct for this scenario: an intercepted FTP session is worse than a lost route. |
| `set local-preference 10` on Invalid | Route installed but never selected if any alternative exists | Conservative first rollout, or transit networks that cannot risk reachability loss. |

If you choose depref during initial rollout, understand its limit here: the
hijack is a **more-specific**, so longest-prefix match in the FIB happens *after*
BGP best-path selection. A depreffed `/25` still wins over a `/24` because they
are different destinations, not competing paths. **For sub-prefix hijacks,
depref does not protect you — you must `deny`.** This is the single most
important operational detail in this appendix.

### Fail-open on cache loss

Note that `RPKI-IN` only denies **Invalid**. If the cache dies and
`expire_interval` elapses, every prefix becomes NotFound and matches sequence
20 — routes are accepted at reduced preference rather than dropped. Routing
survives a validator outage. Never write `route-map RPKI-IN deny` matching
NotFound; on a real internet-facing router that drops most of the DFZ.

## 9.8 Defence in depth alongside RPKI

RPKI ROV validates the **origin AS only**. It does not prove the AS path is real.
An attacker on R1 could prepend `$AS3` to make the origin look correct — the
maxLength pin still stops the `/25`, but an equal-length forged-origin hijack
would validate. Layer the following:

```text
!
! Only accept from each peer what that peer is entitled to originate
ip prefix-list FROM-AS3 seq 5 permit 10.117.117.0/24
ip prefix-list FROM-AS3 seq 10 deny 0.0.0.0/0 le 32
!
! Never accept anyone else's more-specifics of our protected space
ip prefix-list ANTI-SUBPREFIX seq 5 deny 10.117.117.0/24 ge 25
ip prefix-list ANTI-SUBPREFIX seq 10 permit 0.0.0.0/0 le 24
!
! Reject private ASNs and paths that traverse them in production
bgp bestpath as-path multipath-relax
!
router bgp AS2
 address-family ipv4 unicast
  neighbor R1 maximum-prefix 100 80 restart 15
  neighbor R1 route-map RPKI-IN in
  neighbor R1 prefix-list ANTI-SUBPREFIX in
 exit-address-family
!
```

Additional controls worth scheduling:

- **ASPA** (Autonomous System Provider Authorisation) — validates path
  relationships, closing the forged-origin gap RPKI leaves open. Emerging FRR
  support; track it.
- **Peerlock / AS-path filters** — reject any path containing a tier-1 ASN from
  a lateral peer.
- **maximum-prefix** with `restart` — bounds the blast radius of a mass leak.
- **BMP export** to a collector, so RIB changes are observable off-box even if
  the router itself is compromised.
- **RIS Live / BGPalerter / bgp.tools alerting** on any announcement of your
  prefixes by an unexpected origin. This is your out-of-band tripwire when the
  compromised device is your own.

## 9.9 Validation - prove the control works

Do not mark this remediation complete on configuration review alone. Re-run the
attack.

```bash
# 1. Pre-flight: validator's own verdict on the hijack advertisement
curl -s "http://127.0.0.1:8323/api/v1/validity/AS${AS1}/10.117.117.0/25" | jq .
# expect: "state": "invalid"

# 2. Baseline the victim's path
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP"
# expect next hop $R3_R2R3_IP

# 3. Reproduce the hijack from R1 exactly as the red side did
docker exec "$R1_CONTAINER" vtysh \
  -c "configure terminal" \
  -c "ip prefix-list HIJACK seq 5 permit $HIJACK_PREFIX_A" \
  -c "ip prefix-list HIJACK seq 10 permit $HIJACK_PREFIX_B" \
  -c "route-map TO-AS2 permit 10" \
  -c " match ip address prefix-list HIJACK" \
  -c " set community no-export" \
  -c "route-map TO-AS2 permit 20" \
  -c "router bgp $AS1" \
  -c " network $HIJACK_PREFIX_A" \
  -c " network $HIJACK_PREFIX_B" \
  -c "end" \
  -c "clear bgp $R2_R1R2_IP soft out"

sleep 15

# 4. R1 believes it is advertising them
docker exec "$R1_CONTAINER" vtysh \
  -c "show bgp ipv4 unicast neighbors $R2_R1R2_IP advertised-routes"
# expect: both /25s present -- the attacker sees success

# 5. R2 must have rejected them
docker exec "$R2_CONTAINER" vtysh -c "show bgp ipv4 unicast $HIJACK_PREFIX_A"
# expect: "Network not in table"

docker exec "$R2_CONTAINER" vtysh -c "show bgp ipv4 unicast rpki invalid"
# expect: both /25s listed as Invalid

# 6. THE TEST THAT MATTERS -- data plane unchanged
docker exec "$R2_CONTAINER" ip -4 route get "$FTP_SERVER_IP"
# expect: still via $R3_R2R3_IP, NOT $R1_R1R2_IP

# 7. No FTP credentials transit R1
timeout 300 docker exec "$R1_CONTAINER" \
  tcpdump -nni any -A "dst net 10.117.117.0/24 and tcp dst port 21"
# expect: zero packets across a full scheduled-client cycle

# 8. Service still works end to end
docker exec "$CLIENT_CONTAINER" \
  curl -fsS --max-time 12 --ftp-method nocwd \
  --user "${FTP_USERNAME}:${FTP_PASSWORD}" \
  "ftp://${FTP_SERVER_IP}/archive/network-operations-archive.txt"
```

Tear the test hijack back down using the cleanup block in section 5.4.

**Pass criteria:** step 4 succeeds (R1 still emits the routes — the attacker has
no signal of failure), steps 5 and 6 show R2 rejecting them, step 7 captures no
credentials, and step 8 confirms the legitimate workflow is untouched.

## 9.10 Ongoing operations

Monitor the control, or it will silently stop working.

```bash
# Alert if the RTR session drops on any router
for C in "$R1_CONTAINER" "$R2_CONTAINER" "$R3_CONTAINER"; do
  printf '%s: ' "$C"
  docker exec "$C" vtysh -c "show rpki cache-connection" | grep -i connected \
    || echo "RPKI CACHE DOWN"
done

# Alert on any Invalid appearing -- this is a hijack attempt in progress
docker exec "$R2_CONTAINER" vtysh -c "show bgp ipv4 unicast rpki invalid" \
  | grep -v "^$" | tail -n 50

# Validator freshness -- stale objects are as dangerous as no objects
curl -s http://127.0.0.1:8323/status | grep -Ei 'serial|expire|stale|valid'
```

Splunk detections to add alongside section 4:

```spl
index=network source="*/telemetry/r*/frr.log" "rpki"
| search "invalid" OR "connection" OR "expired"
| stats count by host, _raw
| where count > 0
```

```spl
index=network sourcetype=routinator
("rtr" AND ("connection lost" OR "expired" OR "no valid data"))
| table _time host _raw
```

Operational checklist:

| Cadence | Task |
|---|---|
| Continuous | Alert on RTR session state change on any router |
| Continuous | Alert on any prefix entering Invalid state |
| Daily | Validator object counts and per-TAL freshness |
| On change | Update SLURM assertions whenever internal address space changes |
| Quarterly | Re-run the section 9.9 validation drill end to end |
| Quarterly | Audit SLURM file integrity and access control (mode `0644`, root-owned, tracked in version control with reviewed commits) |

## 9.11 Common mistakes in RPKI rollout

1. **Configuring `rpki cache` without loading the module.** `bgpd` silently
   ignores the block; `show rpki cache-connection` returns nothing.
2. **Writing the route-map but never applying it to a neighbor.** The most
   common failure. Validation states are computed and then ignored.
3. **Depreffing Invalids instead of denying them.** Does not stop sub-prefix
   hijacks — see 9.7.
4. **`maxLength 32` in the ROA/SLURM assertion.** Explicitly authorises every
   more-specific in your own space. Pin maxLength to the announced length.
5. **Forgetting SLURM in a private-ASN lab**, then concluding "RPKI didn't
   work" when everything validates NotFound.
6. **A single validator, reachable only over the data plane.** It goes away
   during the incident you built it for.
7. **Denying NotFound.** Drops most of the routing table in production.
8. **Enforcing only on R1.** R1 is the compromised device. Its own policy is
   whatever the attacker says it is. R2 is where the control has to live.
9. **Not re-running the attack after remediation.** Configuration review is not
   validation.
