# PacketDPI Demo

This folder contains a reviewer-friendly demo path for PacketDPI 1.0.

## Build

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Analyze a capture

```powershell
.\build\Release\packetdpi.exe analyze test_dpi.pcap --report demo\analysis_report.txt
```

Expected highlights from the bundled sample:

- 77 packets parsed
- 0 parse errors
- TLS SNI, HTTP Host, and DNS names detected
- Google, YouTube, Facebook, GitHub, TikTok, Spotify, Zoom, Discord, and other app categories classified

## Filter a capture

```powershell
.\build\Release\packetdpi.exe filter test_dpi.pcap demo\filtered.pcap --rules demo\rules.txt
```

The command writes a new PCAP containing forwarded packets only and prints a filtering report with forwarded, dropped, and rule-hit counts.

## Benchmark parser throughput

```powershell
.\build\Release\packetdpi.exe benchmark test_dpi.pcap --iterations 20
```

The benchmark is intentionally simple and local: it repeatedly parses and classifies the bundled capture, then reports packets/sec and MiB/sec.
