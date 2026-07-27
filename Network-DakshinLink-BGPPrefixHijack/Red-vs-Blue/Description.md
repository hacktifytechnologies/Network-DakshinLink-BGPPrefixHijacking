# DakshinLink Route Interception

## Scenario

Two authorised teams are operating against the same regional carrier environment: one testing the trust boundary and one protecting service continuity.

DakshinLink Networks exchanges routes with two Indian service-provider
organisations and supports a legacy operations workflow. Recent support
cases indicate that a protected remote service is business-critical, while
the management platform remains under an expired support licence.

## Objective

Assess or defend the complete management-to-routing trust chain. All
conclusions must be based on live service, packet, authentication and
routing evidence. Legitimate BGP adjacency and the protected workflow must
remain operational.

## Scope

- The assigned challenge VM address and participant-facing port supplied by the platform
- Publicly reachable management and monitoring services discovered during reconnaissance
- Real FRRouting, BGP, Net-SNMP, Apache/PHP, SSH and FTP components
- No router credentials, internal topology values, ASNs, serial number,
  callback address or expected answer are pre-supplied

## Rules

- Work only against the assigned challenge instance.
- Do not stop FRRouting, block every peer, or disable the protected service.
- Do not read operator-only runtime files as a Red participant.
- Treat the environment as a live carrier network and preserve evidence.
- Submit raw discovered findings without a wrapper.
