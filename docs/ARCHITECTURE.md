# Architecture

PacketDPI 1.0 is an offline packet inspection and filtering tool for PCAP files.

```text
PCAP Reader -> Packet Parser -> Classifier -> Rule Manager -> Report/Filtered PCAP
```

## Components

- `PcapReader` reads classic PCAP files and validates global and packet headers.
- `PacketParser` extracts Ethernet, IPv4, TCP, UDP, timestamps, ports, and payload offsets.
- `SNIExtractor`, `HTTPHostExtractor`, and `DNSExtractor` identify domains from TLS Client Hello, HTTP Host, and DNS queries.
- `RuleManager` applies IP, port, domain, wildcard domain, and application rules.
- `packetdpi` exposes `analyze`, `stats`, `filter`, and `benchmark` commands.
- `packet_analyzer` is retained as a low-level educational packet dump tool.

## Threaded Engine Status

The repository includes a compiled multi-stage DPI engine prototype with reader, load-balancer, fast-path, and output-writer components. The public CLI currently uses the deterministic offline filter pipeline as the default because portfolio reviewers should get a command that is predictable on the first run.

## Data Model

Flows are keyed by a five-tuple:

```text
source IP, destination IP, source port, destination port, protocol
```

The classifier updates each flow with the strongest evidence seen so far. A TLS SNI or HTTP Host value overrides generic port-based classification.
