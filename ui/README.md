# PacketDPI Dashboard

This is an optional static dashboard for presenting PacketDPI results. It does not replace the CLI and does not capture live traffic.

Open it directly:

```powershell
start ui\index.html
```

Generate fresh dashboard data from the CLI:

```powershell
.\build\Debug\packetdpi.exe analyze test_dpi.pcap --json ui\packetdpi-report.json
start ui\index.html
```

Then use **Load JSON** and select `ui\packetdpi-report.json`. The page also includes a fallback sample snapshot, so it still opens from `file://` when a reviewer has not generated a report yet.

What it shows:

- PCAP summary metrics.
- Application distribution.
- Top detected domains.
- Rule impact and dropped packets.
- Packet timeline.
- Selected-domain inspector.
- CLI commands to reproduce the analysis.
- JSON loading for real `packetdpi analyze --json` output.

`sample-data.json` is based on the bundled `test_dpi.pcap` demo output. The JavaScript embeds the same sample snapshot so the page works from `file://` without a local server.
