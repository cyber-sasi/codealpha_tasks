# Task 1: Basic Network Sniffer

A small, passive command-line packet sniffer for authorized local-network monitoring and cybersecurity education. It uses Scapy to capture packets and report selected header metadata; packet payloads are not retained, printed, or exported.

## Purpose

This project demonstrates how a network packet is captured and described without turning captured application data into a collection target. Use it only on devices and networks you own or have explicit permission to monitor.

## Features

- Live capture through Scapy, with interface selection and an optional packet limit.
- Stop an unlimited capture safely with `Ctrl+C`.
- Validated filters: `tcp`, `udp`, `icmp`, `arp`, `dns`, `host <IP>`, and `port <PORT>`.
- Packet metadata: number, UTC timestamp, IP addresses, protocol, ports, packet length, TCP flags, and decoded layer names.
- DNS, HTTP-by-port/header, TCP, UDP, ICMP/ICMPv6, and ARP identification.
- Summary counts and top source/destination addresses and protocols.
- Packet inspection and metadata-only CSV/JSON exports.
- Offline tests using constructed Scapy packets; no live traffic needed for tests.

## Technologies

- Python 3.11 or newer
- Scapy 2.6+
- Python standard library (`argparse`, `csv`, `json`, `unittest`, and others)

## Architecture

- `src/main.py` handles command-line arguments, prompts, output, and user-facing errors.
- `src/capture.py` enumerates interfaces and performs passive Scapy capture.
- `src/filters.py` validates the small user filter language and translates it to fixed BPF expressions.
- `src/analyzer.py` extracts a metadata-only `PacketRecord` from each Scapy packet.
- `src/statistics.py` calculates protocol counts and most-common endpoints.
- `src/exporter.py` writes the metadata records as CSV or JSON.
- `src/utils.py` formats the startup banner and summary.

## Folder Structure

```text
Task-1-Network-Sniffer/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── capture.py
│   ├── analyzer.py
│   ├── filters.py
│   ├── statistics.py
│   ├── exporter.py
│   └── utils.py
├── tests/
│   └── test_analyzer.py
├── screenshots/
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

Open a terminal in `Task-1-Network-Sniffer` and create an isolated environment.

### Windows Setup

In PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks environment activation, use the interpreter directly: `\.venv\Scripts\python.exe -m pip install -r requirements.txt`, then replace `python` in later commands with `\.venv\Scripts\python.exe`. Live capture on Windows requires Npcap. Install Npcap from its official distribution and include loopback capture support if you want to monitor localhost traffic. Run the terminal with the privileges required by your system's capture driver.

### Linux / Kali Linux Setup

Install the packet-capture build prerequisites if needed, then create the virtual environment:

```bash
sudo apt update
sudo apt install -y python3-venv libpcap-dev
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Live capture may require elevated privileges and libpcap support. Grant only the privileges necessary for authorized capture; do not run unrelated commands as root.

## Identify a Network Interface

List interfaces Scapy can see:

```powershell
python -m src.main --list-interfaces
```

```bash
python -m src.main --list-interfaces
```

Interface names are platform-specific. Use an exact name from this output, or omit `--interface` to select from the numbered list. Windows may show Npcap device names rather than friendly adapter names. Select a loopback interface only for localhost testing.

## How to Run

From the project root, start an unlimited capture (stop with `Ctrl+C`):

```powershell
python -m src.main
```

To set the interface, capture limit, and filter explicitly:

```powershell
python -m src.main --interface "<interface-name>" --count 100 --filter tcp
```

The same command works in an activated environment on Linux/Kali. Add `sudo` only if your system requires it for capture:

```bash
sudo .venv/bin/python -m src.main --interface "<interface-name>" --count 100 --filter tcp
```

For help:

```text
python -m src.main --help
```

## Usage Examples

```text
python -m src.main --interface "<interface-name>" --count 25 --filter "host 192.0.2.10"
python -m src.main --interface "<interface-name>" --count 50 --filter dns --export dns-metadata.json
python -m src.main --interface "<interface-name>" --count 20 --filter "port 443" --export packets.csv
python -m src.main --interface "<interface-name>" --count 10 --inspect 1
```

Replace placeholders with values from your own system. The example IP is a documentation-only address, not a recommended target.

### Supported Filters

| Filter | Matches |
| --- | --- |
| `tcp` | TCP packets |
| `udp` | UDP packets |
| `icmp` | ICMP and ICMPv6 packets |
| `arp` | ARP packets |
| `dns` | UDP or TCP traffic on port 53 |
| `host <IP>` | Traffic to or from a validated IPv4/IPv6 address |
| `port <PORT>` | Traffic using a port from 0 through 65535 |

Only these forms are accepted. Arbitrary BPF text, shell commands, and combined expressions are rejected. `--count 0` (the default) means unlimited capture; use `Ctrl+C` to stop. Positive counts stop capture automatically.

### Example Output

Addresses and timestamps below are illustrative; actual interfaces, packet content, and counts depend on your machine and test traffic.

```text
Packets (payloads omitted)
#    Timestamp (UTC)                 Source                  Destination             Protocol  Length  Flags
1    2026-01-01T12:00:00.123+00:00   192.0.2.10:53000        192.0.2.53:53           DNS       74      -
2    2026-01-01T12:00:00.456+00:00   192.0.2.10:49152        198.51.100.20:443       TCP       74      S

Capture summary
---------------
Total packets: 2
TCP: 1  UDP: 1  ICMP: 0  ARP: 0
DNS: 1  Other: 0
Top source IPs: 192.0.2.10 (2)
Top destination IPs: 192.0.2.53 (1), 198.51.100.20 (1)
Top protocols: DNS (1), TCP (1)
```

## Inspect and Export

After an interactive capture, enter a packet number to inspect metadata, `e` to export, or `q` to finish. Non-interactive options are also available:

```powershell
python -m src.main --interface "<interface-name>" --count 10 --inspect 1
python -m src.main --interface "<interface-name>" --count 10 --export capture.json
python -m src.main --interface "<interface-name>" --count 10 --export capture.csv
```

The export format is inferred from `.csv` or `.json`. `--format csv` or `--format json` can override it. Neither format contains payload bytes, DNS query names, HTTP paths, cookies, credentials, or application bodies.

## Testing

Tests construct packets locally with Scapy; they do not open an interface or send traffic.

```powershell
python -m unittest discover -s tests -v
```

```bash
python -m unittest discover -s tests -v
```

The suite covers protocol and metadata analysis, supported/rejected filters, statistics, and both export formats.

### Safe Manual Test (localhost only)

Use a loopback interface and generate traffic between processes on your own machine. This does not require visiting a third-party host.

1. In terminal A, start a local HTTP server bound only to loopback:

   ```text
   python -m http.server 8000 --bind 127.0.0.1
   ```

2. In terminal B, list interfaces and identify the loopback adapter (`Npcap Loopback Adapter` on many Windows setups; often `lo` on Linux).
3. Start the capture, replacing the placeholder with that exact interface name:

   ```text
   python -m src.main --interface "<loopback-interface>" --count 10 --filter "port 8000" --export localhost.csv
   ```

4. In terminal C, request the local page:

   ```text
   python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000').read()"
   ```

5. Confirm the capture reports HTTP/TCP metadata, then review the summary and `localhost.csv`. Stop the local server with `Ctrl+C`. If the platform does not expose loopback capture, run the offline tests instead; do not switch to a network you lack permission to monitor.

## Security and Privacy

- The program is passive: it has no packet injection, spoofing, traffic manipulation, credential interception, or attack features.
- Startup displays an authorization warning.
- Packet payloads are never read by the analyzer, displayed, or exported. Only selected headers, protocol layer names, and lengths are retained in memory.
- DNS query names and HTTP paths are deliberately omitted. HTTP identification is metadata-only and uses common port numbers or decoded layer names.
- Captures can still reveal sensitive network metadata such as addresses, ports, timing, and traffic volume. Protect exported files and delete them when no longer needed.
- Use only on networks/devices you own or have explicit permission to monitor, and follow applicable law and organizational policy.

## Limitations

- Live capture depends on operating-system privileges, supported interfaces, and Npcap/libpcap availability.
- Capture filters are intentionally simple and do not allow combining expressions.
- HTTP detection is best-effort based on common ports or Scapy's decoded layer names; encrypted HTTPS is identified as TCP, not decrypted.
- Protocol identification depends on headers available to Scapy. Tunnels, fragments, unusual ports, and malformed traffic may be classified as `OTHER` or a transport protocol.
- Captured packet metadata is kept in memory until the program exits; large unlimited captures can use significant memory.

## Future Improvements

- Add bounded-memory streaming for long-running captures.
- Add optional IPv6-aware protocol and endpoint summary refinements.
- Add a replay mode for user-provided PCAP files without live capture.
- Add richer terminal tables while keeping the dependency footprint small.

## Ethical and Legal Use

This software is for education and authorized defensive monitoring only. You are responsible for obtaining permission before capturing traffic and for securely handling any metadata you export. Unauthorized interception may violate laws, contracts, and privacy expectations.