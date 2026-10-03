# Network Intrusion Detection System Report

## Objective

Implement a lightweight Python NIDS for CodeAlpha Task 4. The project observes authorized local network traffic through Scapy, extracts metadata only, evaluates configurable thresholds, records alert and monitoring events in SQLite, and provides safe demonstrations and exports.

## Scope

Included: optional local packet capture, interface discovery, bounded and continuous capture modes, deterministic metadata rule evaluation, alert cooldown, temporary logical source flags, SQLite storage, CLI statistics/listing, CSV/JSON export, and synthetic tests/demo.

Excluded by design: attack traffic generation, exploitation, credential or payload inspection, packet injection, spoofing, firewall/router/network changes, cloud services, and automatic enforcement. This application uses Scapy directly; Snort and Suricata are not integrated.

## Methodology

Scapy capture runs with packet storage disabled. For each IP packet, the analyzer extracts UTC timestamp, source and destination IP addresses, protocol, packet length, transport ports, and TCP flags. The resulting immutable record has no payload member. The rule engine uses packet timestamps and configurable rolling windows, after which the alert manager suppresses duplicates. Newly generated alerts are passed through the response manager and stored in SQLite. The response is logical only.

The separate demo path supplies synthetic metadata directly to the same detector and database layer. It neither invokes Scapy capture nor transmits packets.

## Detection rules

The defaults in `rules/rules.json` are:

| Rule ID | Description | Threshold | Window | Severity |
|---|---|---:|---:|---|
| `PORT_SCAN` | Distinct TCP destination ports contacted by one source using initial SYN packets | 5 | 10 seconds | MEDIUM |
| `CONNECTION_FLOOD` | Initial TCP SYN attempts from one source to one destination | 20 | 10 seconds | HIGH |
| `ICMP_ANOMALY` | ICMP/ICMPv6 packet count from one source | 30 | 10 seconds | MEDIUM |
| `REPEATED_PATTERN` | Repeated source/destination/protocol/destination-port tuple | 12 | 5 seconds | LOW |

Thresholds are inclusive. Rules have explicit enabled state, severity, description, and positive threshold/window validation. The rules provide lightweight anomaly signals; they do not prove malicious intent or successful connection establishment.

## Alert workflow

For each qualifying packet window, the detector requests an alert. Alerts include ID, rule, time, severity, source/destination metadata, protocol/ports, description, reason, and status. Duplicate keys (rule, source, destination) are suppressed during a configurable cooldown. An unsuppressed alert is persisted after its response status and severity have been finalized.

## Response mechanism

The response manager records a source's expiry time in an in-memory logical flag set and labels the resulting alert `FLAGGED`. Repeated generated alerts from the same source escalate severity one level, capped at HIGH. No packet filtering or operating-system/network configuration is performed. Flags expire and disappear when the process ends.

## Test results

The pytest suite covers Scapy IPv4/IPv6 metadata extraction without retaining payload, TCP port-scan and repeated connection thresholds, ICMP and repeated-pattern detection, disabled rules and window boundaries, alert metadata and cooldown, response flag/escalation behavior, SQLite persistence/filtering/statistics, metadata-only CSV/JSON export, CLI validation, help, and safe demo persistence. The full suite passed: **27 passed**. Tests run against synthetic packets and temporary databases; no live packet capture is required.

## Demonstration results

The safe demo uses seven synthetic TCP SYN metadata records, from documentation address `192.0.2.10` to `192.0.2.20`, with different destination ports. At the default fifth-port threshold the port-scan rule generates a MEDIUM alert. The response marks it `FLAGGED`; the event and seven metadata packet counts are persisted in the selected SQLite database. No packets are generated or sent.

## Limitations

Capture availability and visibility depend on permissions, installed drivers, interface selection, and network topology. Threshold rules can yield false positives and cannot replace a production IDS or analyst review. Detection is limited to metadata and simple patterns; it does not inspect payloads, validate connection outcomes, or implement an enforcement control. The temporary flag is not persisted.

## Conclusion

The project satisfies the educational NIDS goal with a modular, locally testable implementation and explicit safety boundaries. It supports authorized monitoring and a repeatable zero-network-traffic demonstration while keeping event records limited to security metadata.
