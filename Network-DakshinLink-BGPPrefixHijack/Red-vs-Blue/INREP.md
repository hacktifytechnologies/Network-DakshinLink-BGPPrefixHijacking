# Incident Notification Report (INREP)

**Cyber Exercise - Network Component Exploitation**  
**Scenario:** DakshinLink Route Interception  
**Report ID:** IN-NWR-CARRIER-01

## 1. Current Situation

**Date/Time:** [UTC timestamp]  
**Threat Level:** Critical  
**Description:** An external source used the carrier portal's SNMP-derived
default credential and diagnostic command injection to obtain root execution
on the DakshinLink edge router. More-specific BGP routes redirected a live
FTP authentication flow through the compromised router.

## 2. Initial Evidence

- Source IP from portal access log and `audit.jsonl`: [live value]
- Injected diagnostic value: [live value]
- Root SSH session evidence: [timestamp/process]
- Affected dynamically generated prefixes: [live values]
- R2 selected next hop before/after: [live values]
- Transit PCAP FTP evidence: [packet/timestamp]

## 3. Immediate Actions

1. Preserve portal, SSH, FRR, FTP and PCAP evidence.
2. Block only the confirmed external source.
3. End the confirmed injected shell.
4. Withdraw malicious more-specifics without stopping FRR.
5. Verify both legitimate BGP peers and the FTP workflow.

## 4. Service Status

- `frr.service`: [active/inactive]
- TCP/179 inside R1: [up/down]
- Legitimate BGP peers: [state]
- Direct AS2-to-AS3 FTP path: [normal/diverted]
- Protected FTP workflow: [operational/degraded]

## 5. POC

[Attach timestamped portal, route, process and packet evidence.]
