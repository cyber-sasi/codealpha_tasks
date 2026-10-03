# CodeAlpha Task 4: Network Intrusion Detection System

A lightweight, local network intrusion detection system (NIDS) for **authorized monitoring**. It uses Scapy to inspect packet metadata, applies deterministic configurable rules, stores alerts in SQLite, and offers CSV/JSON export. It does not transmit packets, inspect or save payload contents, change firewall/network settings, or depend on a cloud service.

> **Authorization warning:** Capture traffic only on systems and networks you own or have explicit permission to monitor. Packet capture may require administrator privileges and a supported capture driver. The synthetic demo does not capture or transmit network traffic.

## Objective

Build and demonstrate a modular NIDS that monitors selected traffic, detects configurable suspicious patterns, records severity-rated alerts and safe logical responses, and can be tested without a live interface.

## CodeAlpha Task 4 requirement mapping

| Requirement | Implementation |
|---|---|
| Network monitoring and interface selection | Scapy-backed `--interface`, `--count`, `--monitor`, and `--list-interfaces` |
| Configurable rules and alerts | `rules/rules.json`, deterministic time-window engine, LOW/MEDIUM/HIGH alerts |
| Continuous monitoring | Scapy capture with `store=False`; Ctrl+C ends monitoring gracefully |
| Defensive response | In-memory temporary source flag, repeat-detection severity escalation, and SQLite logging only |
| Dashboard/visualization | Optional; terminal statistics and alert listings are available |
| Event storage and exports | Local SQLite; metadata-only CSV and JSON output |
| Safe practical demonstration | `--demo` supplies synthetic packet metadata directly to the detector; no packets are sent |

## Features

- Captures a controlled number of packets or monitors continuously on a selected interface.
- Extracts only timestamp, IPs, protocol, ports, packet length, and TCP flags.
- Never puts payload bytes into the metadata model, database schema, or exports.
- Detects a source contacting many TCP destination ports, repeated TCP SYN attempts to one destination, frequent ICMP/ICMPv6 traffic, and repeated matching traffic patterns.
- Supports configurable thresholds, time windows, enabled state, severity, deduplication cooldown, and temporary flag duration.
- Stores alerts, packet totals, and protocol distribution in SQLite.
- Filters alert listings by severity and source IP; presents alert statistics.
- Runs unit tests using synthetic packet objects and metadata; tests do not require live capture.

## Architecture and workflow

```text
Scapy capture (or --demo synthetic metadata)
                  |
           metadata parser
                  |
       deterministic RuleEngine
                  |
        AlertManager (cooldown)
                  |
    ResponseManager (logical flag)
                  |
     SQLite alerts and counters
                  |
       CLI listing / stats / export
```

`capture.py` is the only module that starts live capture. The parser (`analyzer.py`) returns an immutable metadata record; it has no payload property. `rules.py` evaluates that record using packet timestamps, and `detector.py` coordinates matching, duplicate suppression, and response. `database.py` stores only the selected metadata and aggregate counters. CSV/JSON exports use a fixed allowlist of alert fields.

## Technologies

- Python 3.11+
- Scapy 2.x (capture and packet layer decoding)
- SQLite (`sqlite3`, Python standard library)
- pytest
- Python standard library for argument parsing, CSV/JSON, typing, and timestamps

This project is a Python/Scapy NIDS. **Snort and Suricata are not used or integrated.**

## Project structure

```text
Task-4-Network-Intrusion-Detection-System/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── capture.py
│   ├── analyzer.py
│   ├── rules.py
│   ├── detector.py
│   ├── alerts.py
│   ├── response.py
│   ├── database.py
│   ├── exporter.py
│   └── utils.py
├── rules/
│   └── rules.json
├── tests/
│   └── test_nids.py
├── screenshots/
├── reports/
│   └── nids_report.md
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

From the project directory in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Use a supported Python 3.11 or newer installation. The project does not install or enable a packet-capture driver automatically.

### Windows and Npcap

On Windows, install Npcap from its official distribution if live packet capture needs it. Follow your organization's endpoint policy and the Npcap installer guidance. Run the terminal with the permissions required by the installed driver. The application reports capture errors and suggests checking Npcap and permissions; it does not elevate itself or change system settings. The `--demo`, storage, export, and test workflows do not need Npcap.

## Interface discovery

```powershell
python -m src.main --list-interfaces
```

Choose an interface name exactly as printed. Names differ between operating systems and machines; none is hardcoded. If no interface is listed, check Scapy/Npcap installation and permissions.

## Controlled monitoring

Capture a bounded number of packets:

```powershell
python -m src.main --interface "<interface-from-list>" --count 100
```

Monitor until Ctrl+C:

```powershell
python -m src.main --interface "<interface-from-list>" --monitor
```

Both modes require explicit authorization. Capture uses `store=False`; packets are analyzed as they arrive and are not retained by Scapy. Non-IP frames are ignored. If capture is unavailable, verify the selected name and local capture permissions.

## Safe synthetic demonstration

```powershell
python -m src.main --demo --db demo.sqlite3
```

This creates seven in-memory TCP SYN metadata records from the documentation-only example address `192.0.2.10` to `192.0.2.20`, with distinct destination ports. It sends no traffic and starts no capture. With default rules, the fifth distinct port crosses the port-scan threshold and produces a MEDIUM alert; the event is logically flagged and saved to the selected local database.

Use `--cooldown-seconds 0` to disable duplicate suppression or `--flag-seconds 120` to adjust logical flag duration. Neither setting changes network behavior.

## Detection rules

Rules live in `rules/rules.json`. Each rule has an ID, description, severity, threshold, time window, and enabled flag. Rule IDs supplied by default:

| Rule | Matching behavior | Default threshold / window | Severity |
|---|---|---:|---|
| `PORT_SCAN` | Distinct TCP destination ports for a source; only initial SYN packets | 5 ports / 10 s | MEDIUM |
| `CONNECTION_FLOOD` | TCP initial SYN packets from a source to one destination | 20 packets / 10 s | HIGH |
| `ICMP_ANOMALY` | ICMP or ICMPv6 packets from a source | 30 packets / 10 s | MEDIUM |
| `REPEATED_PATTERN` | Same source, destination, protocol, and destination port | 12 packets / 5 s | LOW |

Thresholds trigger at `>= threshold`. Detection uses packet timestamps and deterministic rolling windows. TCP connection rules use SYN without ACK as a connection-attempt indicator; they do not infer that a connection succeeded. Alerts are deduplicated by rule/source/destination during the configured cooldown. Rule thresholds can be adjusted in JSON; malformed rules fail with an explicit error.

Display the currently loaded rules:

```powershell
python -m src.main --rules
```

Supply an alternate JSON file with `--rules-file PATH`.

## Alerts and response

An alert contains a UUID, rule ID, UTC timestamp, severity, source/destination metadata, protocol, ports where available, description, detection reason, and status. The response manager marks the source as `FLAGGED` in the alert and holds a temporary in-memory flag. A subsequent alert from that source escalates severity by one level (capped at HIGH). The flag expires after the configured duration.

This is a **logical/simulated response** for the student project. It does not block packets, alter the Windows firewall, modify a router, reconfigure a network, or contact an external system. The logical flag is in-memory and is not restored after process exit.

## Database, listings, and statistics

By default, data is stored in `nids_events.sqlite3` in the current directory. Set a different path with `--db PATH`. The database includes alert records, total metadata records processed, and protocol counts. Payload bytes are not stored.

```powershell
python -m src.main --show-alerts
python -m src.main --show-alerts --severity HIGH --limit 20
python -m src.main --show-alerts --source 192.0.2.10
python -m src.main --stats
```

Statistics show the total packets processed, total alerts, alerts by severity and rule, top alert-associated source IPs, and protocol distribution. These counters describe this selected local database, not all network traffic on the host. `--limit` must be a positive integer.

## CSV and JSON export

```powershell
python -m src.main --export alerts.csv --format csv
python -m src.main --export alerts.json --format json --db demo.sqlite3
```

Exports include only allowlisted alert fields (security metadata); they do not include packet payloads. Use an appropriate protected local destination for exported security data. Generated databases, CSV, and JSON files are excluded by `.gitignore`.

## Testing

```powershell
python -m pytest -q
```

Tests build synthetic Scapy packets or `PacketMetadata` records and use temporary SQLite databases. They do not open a capture interface or generate network traffic.

## Example output

The exact UUID and timestamp vary:

```text
[MEDIUM] PORT_SCAN from 192.0.2.10: Possible TCP port scan 5 distinct destination ports from 192.0.2.10 within 10s (threshold 5). (response=FLAGGED, id=<alert-uuid>)
Demo complete: 1 alert(s) stored in demo.sqlite3; source temporarily flagged in memory: 192.0.2.10.
```

## Security, privacy, and limitations

- Use only on authorized networks and hosts.
- No attack generation, exploitation, packet injection, spoofing, credential collection, or evasion features.
- No raw packet payload logging or export.
- No automatic firewall, router, external system, or network configuration changes.
- Threshold-based rules may produce false positives and are not a substitute for a mature IDS, incident response process, or network security monitoring program.
- Capture visibility depends on interface, driver, privileges, and network topology; switched networks generally do not expose unrelated unicast traffic.
- The in-memory flag is informational and does not enforce blocking.
- The packet count/statistics cover metadata records successfully parsed as IP packets.
- This project is not a replacement for Snort/Suricata and does not consume their rulesets.

## Future improvements

- Add configurable alert destinations that remain local and privacy-preserving.
- Add severity/rule filtering to export.
- Add interface-level integration tests using an isolated lab and explicit opt-in.
- Add a small local dashboard that consumes the existing SQLite schema.
- Add IPv6-specific rules and configurable protocol-aware connection heuristics.

## Ethical and legal use

Only capture or analyze network traffic when you own the systems or have explicit written authorization. Follow local law, organizational policies, and data-retention requirements. Keep the database and exports protected because even metadata can be sensitive. Prefer `--demo` for presentations and testing where live capture authorization is absent.
