# Benchmarks

PacketDPI includes a lightweight local benchmark command:

```powershell
.\build\Release\packetdpi.exe benchmark test_dpi.pcap --iterations 20
```

The benchmark reports:

- parsed packet count
- total bytes processed
- elapsed time
- packets per second
- MiB per second

Use a larger PCAP for meaningful performance claims. The bundled `test_dpi.pcap` is intentionally small so CI and first-run demos stay fast.
