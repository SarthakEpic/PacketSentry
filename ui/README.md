# PacketDPI Dashboard

This is an optional static dashboard for presenting PacketDPI results. It does not replace the CLI and does not capture live traffic.

Open it directly:

```powershell
start ui\index.html
```

What it shows:

- PCAP summary metrics.
- Application distribution.
- Top detected domains.
- Rule impact and dropped packets.
- Packet timeline.
- Selected-domain inspector.
- CLI commands to reproduce the analysis.

The dashboard currently uses `sample-data.json`, based on the bundled `test_dpi.pcap` demo output. The JavaScript also embeds the same sample snapshot so the page works from `file://` without a local server.
