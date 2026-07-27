# Situation Report (SITREP)

**Scenario:** DakshinLink Route Interception  
**Incident ID:** SITREP-NWR-CARRIER-01  
**Prepared By:** [Blue Team analyst]

## 1. Incident Overview

The incident combined exposed SNMP metadata, default credential derivation,
authenticated command injection, privileged router access and selective BGP
more-specific route origination. Live FTP credentials traversed R1 only
after the route change.

## 2. Timeline

| Time | Event | Evidence |
|---|---|---|
| [time] | SNMP/portal reconnaissance | access/snmpd logs |
| [time] | Admin login | Apache and audit JSONL |
| [time] | Diagnostic injection | `diagnostic_execute` |
| [time] | Root router session | R1 auth/process/network state |
| [time] | BGP more-specifics originated | FRR config/log/RIB |
| [time] | FTP authentication crossed R1 | transit PCAP |
| [time] | Containment and withdrawal | route and session evidence |
| [time] | Service restored | availability output |

## 3. Scope and Impact

- Affected component: DakshinLink R1
- Affected control plane: eBGP advertisements to AS2/AS3
- Affected data plane: client-to-FTP control traffic
- Exposed information: live FTP username and password
- Availability: [maintained/degraded]

## 4. Response

**Containment:** [source-specific block, shell termination, route withdrawal]  
**Eradication:** [portal validation, credential rotation, SSH restriction, BGP filtering]  
**Recovery:** [legitimate peers, direct path and FTP proof]

## 5. Current State

Current-state availability is UP only when `frr.service`, TCP/179,
legitimate peers, direct routing, portal health and FTP health pass, with
no active shell or hijack.

## 6. POC

[Attach screenshots and exported evidence with hashes.]
