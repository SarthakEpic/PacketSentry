# Security and Ethics

PacketDPI is designed for offline analysis of PCAP files that you own or have explicit permission to inspect.

Responsible use:

- Use it for education, lab captures, portfolio review, defensive research, and controlled enterprise analysis.
- Do not use it to intercept live traffic without consent and legal authorization.
- Treat captured packets as sensitive data because PCAP files can contain private metadata and payloads.
- Share sample captures only when they are synthetic, anonymized, or explicitly approved for release.

Current privacy boundary:

- The default CLI reads local PCAP files and writes local reports or filtered PCAP files.
- It does not phone home, open sockets, or perform live network interception.
