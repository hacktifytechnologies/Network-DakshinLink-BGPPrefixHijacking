# Red Team Engagement Report - NWR-CARRIER-01

**Scenario:** DakshinLink Route Interception  
**Engagement:** Red-vs-Blue network-component exercise  
**Classification:** Training

## Executive Summary

Testing demonstrated a complete carrier compromise chain. A real SNMP
service disclosed a dynamically generated device serial used as the portal's
default administrator password. The authenticated Diagnostics function
accepted a base64 value and concatenated it into a command executed as root
on the FRRouting edge. The compromised router then selectively originated
more-specific routes toward the client AS, causing actual clear-text FTP
credentials to transit R1.

## Finding 1 - SNMP serial used as default portal credential (High)

**Evidence:** [SNMP OID, serial and successful login timestamps]  
**Impact:** Remote authentication to the carrier management portal.  
**Recommendation:** Use independent credentials, rotate defaults, restrict
SNMP and deploy SNMPv3 authentication/privacy.

## Finding 2 - Authenticated diagnostic command injection (Critical)

**Evidence:** [base64 request, decoded command, root `id` output, SSH log]  
**Impact:** Root command execution on the live carrier router.  
**Recommendation:** Replace concatenation with a fixed allowlist, use a
non-root forced command and validate every server-side diagnostic action.

## Finding 3 - Selective BGP prefix hijack and credential interception (Critical)

**Evidence:** [live ASNs, more-specific prefixes, route maps, R2 FIB change,
R1 PCAP `USER`/`PASS`]  
**Impact:** Adversary-in-the-middle access to unencrypted inter-carrier
service traffic while the protected workflow remains operational.  
**Recommendation:** Implement strict prefix policy, maximum-prefix controls,
route monitoring and encrypted application protocols.

## Attack Path

1. Discover HTTP and UDP monitoring services.
2. Read error manual and dynamic topology.
3. Obtain the serial from SNMP and authenticate.
4. Exploit Diagnostics to execute commands as root on R1.
5. Map the live AS topology and protected FTP subnet.
6. Advertise two more-specific routes only toward AS2.
7. Capture actual FTP credentials on R1.

## Operational Impact

The management-plane flaw became a control-plane compromise and then a
data-plane interception. The strongest evidence is the correlation between
the portal source IP, R1 root session, BGP route change and FTP packets.
