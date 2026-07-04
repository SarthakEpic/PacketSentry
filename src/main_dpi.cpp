#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "dpi_engine.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "sni_extractor.h"
#include "types.h"

using namespace DPI;
using namespace PacketAnalyzer;

namespace {

struct CliOptions {
    std::string command;
    std::string input_file;
    std::string output_file;
    std::string report_file;
    std::string rules_file;
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::vector<uint16_t> block_ports;
    int load_balancers = 2;
    int fps_per_lb = 2;
    int max_packets = -1;
    int iterations = 3;
    bool verbose = false;
};

struct CaptureSummary {
    uint64_t total_packets = 0;
    uint64_t parsed_packets = 0;
    uint64_t parse_errors = 0;
    uint64_t ipv4_packets = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t payload_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t sni_hits = 0;
    uint64_t http_host_hits = 0;
    uint64_t dns_hits = 0;
    std::map<AppType, uint64_t> app_counts;
    std::map<std::string, uint64_t> domain_counts;
};

struct FilterFlow {
    AppType app = AppType::UNKNOWN;
    std::string domain;
    bool blocked = false;
};

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::optional<AppType> parseAppType(const std::string& value) {
    std::string target = lower(value);
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        AppType app = static_cast<AppType>(i);
        if (lower(appTypeToString(app)) == target) {
            return app;
        }
    }
    return std::nullopt;
}

bool parsePort(const std::string& value, uint16_t& out) {
    try {
        int parsed = std::stoi(value);
        if (parsed < 1 || parsed > 65535) {
            return false;
        }
        out = static_cast<uint16_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parseIPv4(const std::string& ip, uint32_t& out) {
    uint32_t result = 0;
    uint32_t octet = 0;
    int shift = 0;
    int dots = 0;

    for (char c : ip) {
        if (c == '.') {
            if (octet > 255 || dots >= 3) {
                return false;
            }
            result |= (octet << shift);
            shift += 8;
            octet = 0;
            dots++;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + static_cast<uint32_t>(c - '0');
            if (octet > 255) {
                return false;
            }
        } else {
            return false;
        }
    }

    if (octet > 255 || dots != 3) {
        return false;
    }

    out = result | (octet << shift);
    return true;
}

bool parsePositiveInt(const std::string& value, int& out) {
    try {
        int parsed = std::stoi(value);
        if (parsed <= 0) {
            return false;
        }
        out = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

void printUsage(const char* program) {
    std::cout << R"(PacketDPI 1.0 - offline packet inspection and filtering

Usage:
  )" << program << R"( analyze <input.pcap> [--max N] [--report file]
  )" << program << R"( stats <input.pcap>
  )" << program << R"( filter <input.pcap> <output.pcap> [rules/options]
  )" << program << R"( benchmark <input.pcap> [--iterations N]

Filter rules:
  --block-ip <ip>          Block traffic from a source IPv4 address
  --block-domain <domain>  Block a domain or wildcard such as *.youtube.com
  --block-app <app>        Block a classified app such as YouTube or GitHub
  --block-port <port>      Block a destination port
  --rules <file>           Load a rules file

Other options:
  --verbose                Print additional details

Examples:
  )" << program << R"( analyze test_dpi.pcap --report demo/report.txt
  )" << program << R"( filter test_dpi.pcap filtered.pcap --block-domain *.youtube.com
  )" << program << R"( benchmark test_dpi.pcap --iterations 10
)";
}

bool parseArgs(int argc, char* argv[], CliOptions& options) {
    if (argc < 3) {
        return false;
    }

    options.command = lower(argv[1]);
    options.input_file = argv[2];

    int i = 3;
    if (options.command == "filter") {
        if (argc < 4) {
            return false;
        }
        options.output_file = argv[3];
        i = 4;
    }

    for (; i < argc; i++) {
        std::string arg = argv[i];
        auto needValue = [&](const std::string& name) -> std::optional<std::string> {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                return std::nullopt;
            }
            return std::string(argv[++i]);
        };

        if (arg == "--block-ip") {
            auto value = needValue(arg);
            if (!value) return false;
            options.block_ips.push_back(*value);
        } else if (arg == "--block-domain") {
            auto value = needValue(arg);
            if (!value) return false;
            options.block_domains.push_back(*value);
        } else if (arg == "--block-app") {
            auto value = needValue(arg);
            if (!value) return false;
            options.block_apps.push_back(*value);
        } else if (arg == "--block-port") {
            auto value = needValue(arg);
            if (!value) return false;
            uint16_t port = 0;
            if (!parsePort(*value, port)) {
                std::cerr << "Invalid port: " << *value << "\n";
                return false;
            }
            options.block_ports.push_back(port);
        } else if (arg == "--rules") {
            auto value = needValue(arg);
            if (!value) return false;
            options.rules_file = *value;
        } else if (arg == "--report") {
            auto value = needValue(arg);
            if (!value) return false;
            options.report_file = *value;
        } else if (arg == "--max") {
            auto value = needValue(arg);
            if (!value || !parsePositiveInt(*value, options.max_packets)) return false;
        } else if (arg == "--iterations") {
            auto value = needValue(arg);
            if (!value || !parsePositiveInt(*value, options.iterations)) return false;
        } else if (arg == "--lbs") {
            auto value = needValue(arg);
            if (!value || !parsePositiveInt(*value, options.load_balancers)) return false;
        } else if (arg == "--fps") {
            auto value = needValue(arg);
            if (!value || !parsePositiveInt(*value, options.fps_per_lb)) return false;
        } else if (arg == "--verbose") {
            options.verbose = true;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
    }

    return options.command == "analyze" ||
           options.command == "stats" ||
           options.command == "filter" ||
           options.command == "benchmark";
}

size_t payloadOffset(const RawPacket& raw, const ParsedPacket& parsed) {
    if (!parsed.has_ip || raw.data.size() < 14) {
        return raw.data.size();
    }

    size_t offset = 14;
    uint8_t ip_ihl = raw.data[14] & 0x0F;
    offset += static_cast<size_t>(ip_ihl) * 4;

    if (parsed.has_tcp) {
        if (offset + 13 >= raw.data.size()) {
            return raw.data.size();
        }
        uint8_t tcp_offset = (raw.data[offset + 12] >> 4) & 0x0F;
        offset += static_cast<size_t>(tcp_offset) * 4;
    } else if (parsed.has_udp) {
        offset += 8;
    }

    return std::min(offset, raw.data.size());
}

void classifyPacket(const RawPacket& raw, const ParsedPacket& parsed, CaptureSummary& summary) {
    AppType app = AppType::UNKNOWN;
    std::string domain;

    size_t offset = payloadOffset(raw, parsed);
    size_t payload_length = offset < raw.data.size() ? raw.data.size() - offset : 0;
    const uint8_t* payload = payload_length > 0 ? raw.data.data() + offset : nullptr;

    if (payload_length > 0) {
        summary.payload_packets++;
    }

    if (payload && parsed.has_tcp && parsed.dest_port == 443) {
        auto sni = SNIExtractor::extract(payload, payload_length);
        if (sni) {
            domain = *sni;
            app = sniToAppType(domain);
            summary.sni_hits++;
        }
    }

    if (payload && domain.empty() && parsed.has_tcp && parsed.dest_port == 80) {
        auto host = HTTPHostExtractor::extract(payload, payload_length);
        if (host) {
            domain = *host;
            app = sniToAppType(domain);
            summary.http_host_hits++;
        }
    }

    if (payload && parsed.has_udp && (parsed.dest_port == 53 || parsed.src_port == 53)) {
        auto query = DNSExtractor::extractQuery(payload, payload_length);
        if (query) {
            domain = *query;
            app = AppType::DNS;
            summary.dns_hits++;
        }
    }

    if (app == AppType::UNKNOWN) {
        if (parsed.dest_port == 443) app = AppType::HTTPS;
        else if (parsed.dest_port == 80) app = AppType::HTTP;
        else if (parsed.dest_port == 53 || parsed.src_port == 53) app = AppType::DNS;
    }

    summary.app_counts[app]++;
    if (!domain.empty()) {
        summary.domain_counts[domain]++;
    }
}

bool summarizeCapture(const std::string& input_file, int max_packets, CaptureSummary& summary) {
    PcapReader reader;
    if (!reader.open(input_file)) {
        return false;
    }

    RawPacket raw;
    ParsedPacket parsed;
    while (reader.readNextPacket(raw)) {
        summary.total_packets++;
        summary.total_bytes += raw.data.size();

        if (PacketParser::parse(raw, parsed)) {
            summary.parsed_packets++;
            if (parsed.has_ip) summary.ipv4_packets++;
            if (parsed.has_tcp) summary.tcp_packets++;
            if (parsed.has_udp) summary.udp_packets++;
            if (parsed.has_ip && (parsed.has_tcp || parsed.has_udp)) {
                classifyPacket(raw, parsed, summary);
            }
        } else {
            summary.parse_errors++;
        }

        if (max_packets > 0 && static_cast<int>(summary.total_packets) >= max_packets) {
            break;
        }
    }

    reader.close();
    return true;
}

std::string renderSummary(const CaptureSummary& summary) {
    std::ostringstream out;
    out << "PacketDPI Capture Report\n";
    out << "========================\n\n";
    out << "Packets read:        " << summary.total_packets << "\n";
    out << "Packets parsed:      " << summary.parsed_packets << "\n";
    out << "Parse errors:        " << summary.parse_errors << "\n";
    out << "IPv4 packets:        " << summary.ipv4_packets << "\n";
    out << "TCP packets:         " << summary.tcp_packets << "\n";
    out << "UDP packets:         " << summary.udp_packets << "\n";
    out << "Payload packets:     " << summary.payload_packets << "\n";
    out << "Total bytes:         " << summary.total_bytes << "\n";
    out << "TLS SNI hits:        " << summary.sni_hits << "\n";
    out << "HTTP Host hits:      " << summary.http_host_hits << "\n";
    out << "DNS query hits:      " << summary.dns_hits << "\n\n";

    out << "Application distribution\n";
    out << "------------------------\n";
    for (const auto& [app, count] : summary.app_counts) {
        double pct = summary.parsed_packets > 0
            ? (100.0 * static_cast<double>(count) / static_cast<double>(summary.parsed_packets))
            : 0.0;
        out << std::setw(16) << std::left << appTypeToString(app)
            << std::setw(8) << std::right << count
            << "  " << std::fixed << std::setprecision(1) << pct << "%\n";
    }

    out << "\nTop domains\n";
    out << "-----------\n";
    std::vector<std::pair<std::string, uint64_t>> domains(summary.domain_counts.begin(),
                                                           summary.domain_counts.end());
    std::sort(domains.begin(), domains.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    size_t limit = std::min<size_t>(10, domains.size());
    for (size_t i = 0; i < limit; i++) {
        out << std::setw(36) << std::left << domains[i].first
            << domains[i].second << "\n";
    }
    if (domains.empty()) {
        out << "(none detected)\n";
    }

    return out.str();
}

int runAnalyze(const CliOptions& options) {
    CaptureSummary summary;
    if (!summarizeCapture(options.input_file, options.max_packets, summary)) {
        return 1;
    }

    std::string report = renderSummary(summary);
    std::cout << report;

    if (!options.report_file.empty()) {
        std::ofstream file(options.report_file);
        if (!file.is_open()) {
            std::cerr << "Could not write report: " << options.report_file << "\n";
            return 1;
        }
        file << report;
        std::cout << "\nReport written to: " << options.report_file << "\n";
    }

    return 0;
}

int runFilter(const CliOptions& options) {
    RuleManager rules;
    if (!options.rules_file.empty() && !rules.loadRules(options.rules_file)) {
        std::cerr << "Could not load rules file: " << options.rules_file << "\n";
        return 1;
    }

    for (const auto& ip : options.block_ips) {
        uint32_t parsed_ip = 0;
        if (!parseIPv4(ip, parsed_ip)) {
            std::cerr << "Invalid IPv4 address: " << ip << "\n";
            return 1;
        }
        rules.blockIP(parsed_ip);
    }
    for (const auto& domain : options.block_domains) {
        rules.blockDomain(domain);
    }
    for (const auto& app_name : options.block_apps) {
        auto app = parseAppType(app_name);
        if (!app) {
            std::cerr << "Unknown app: " << app_name << "\n";
            return 1;
        }
        rules.blockApp(*app);
    }
    for (uint16_t port : options.block_ports) {
        rules.blockPort(port);
    }

    PcapReader reader;
    if (!reader.open(options.input_file)) {
        return 1;
    }

    std::ofstream output(options.output_file, std::ios::binary);
    if (!output.is_open()) {
        std::cerr << "Could not open output file: " << options.output_file << "\n";
        return 1;
    }
    const auto& header = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&header), sizeof(header));

    std::unordered_map<FiveTuple, FilterFlow, FiveTupleHash> flows;
    uint64_t total = 0;
    uint64_t parsed_count = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;
    std::map<AppType, uint64_t> app_counts;
    std::map<std::string, uint64_t> blocked_reasons;

    RawPacket raw;
    ParsedPacket parsed;
    while (reader.readNextPacket(raw)) {
        total++;
        bool should_drop = false;

        if (PacketParser::parse(raw, parsed) && parsed.has_ip && (parsed.has_tcp || parsed.has_udp)) {
            parsed_count++;

            FiveTuple tuple{};
            if (!parseIPv4(parsed.src_ip, tuple.src_ip) ||
                !parseIPv4(parsed.dest_ip, tuple.dst_ip)) {
                should_drop = false;
            } else {
                tuple.src_port = parsed.src_port;
                tuple.dst_port = parsed.dest_port;
                tuple.protocol = parsed.protocol;

                FilterFlow& flow = flows[tuple];
                size_t offset = payloadOffset(raw, parsed);
                size_t payload_length = offset < raw.data.size() ? raw.data.size() - offset : 0;
                const uint8_t* payload = payload_length > 0 ? raw.data.data() + offset : nullptr;

                if (payload && parsed.has_tcp && parsed.dest_port == 443 &&
                    (flow.domain.empty() || flow.app == AppType::UNKNOWN || flow.app == AppType::HTTPS)) {
                    auto sni = SNIExtractor::extract(payload, payload_length);
                    if (sni) {
                        flow.domain = *sni;
                        flow.app = sniToAppType(flow.domain);
                    }
                }

                if (payload && parsed.has_tcp && parsed.dest_port == 80 &&
                    (flow.domain.empty() || flow.app == AppType::UNKNOWN || flow.app == AppType::HTTP)) {
                    auto host = HTTPHostExtractor::extract(payload, payload_length);
                    if (host) {
                        flow.domain = *host;
                        flow.app = sniToAppType(flow.domain);
                    }
                }

                if (payload && parsed.has_udp && (parsed.dest_port == 53 || parsed.src_port == 53) &&
                    flow.domain.empty()) {
                    auto query = DNSExtractor::extractQuery(payload, payload_length);
                    if (query) {
                        flow.domain = *query;
                        flow.app = AppType::DNS;
                    }
                }

                if (flow.app == AppType::UNKNOWN) {
                    if (parsed.dest_port == 443) flow.app = AppType::HTTPS;
                    else if (parsed.dest_port == 80) flow.app = AppType::HTTP;
                    else if (parsed.dest_port == 53 || parsed.src_port == 53) flow.app = AppType::DNS;
                }

                auto reason = rules.shouldBlock(tuple.src_ip, tuple.dst_port, flow.app, flow.domain);
                if (reason) {
                    flow.blocked = true;
                    blocked_reasons[reason->detail]++;
                }

                should_drop = flow.blocked;
                app_counts[flow.app]++;
            }
        }

        if (should_drop) {
            dropped++;
        } else {
            forwarded++;
            PcapPacketHeader packet_header = raw.header;
            output.write(reinterpret_cast<const char*>(&packet_header), sizeof(packet_header));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }
    }

    reader.close();
    output.close();

    if (!output.good()) {
        std::cerr << "Failed while writing output file: " << options.output_file << "\n";
        return 1;
    }

    std::cout << "PacketDPI Filter Report\n";
    std::cout << "=======================\n\n";
    std::cout << "Input:       " << options.input_file << "\n";
    std::cout << "Output:      " << options.output_file << "\n";
    std::cout << "Packets:     " << total << "\n";
    std::cout << "Parsed:      " << parsed_count << "\n";
    std::cout << "Forwarded:   " << forwarded << "\n";
    std::cout << "Dropped:     " << dropped << "\n";
    std::cout << "Flows:       " << flows.size() << "\n\n";

    if (!blocked_reasons.empty()) {
        std::cout << "Blocked reasons\n";
        std::cout << "---------------\n";
        for (const auto& [reason, count] : blocked_reasons) {
            std::cout << std::setw(32) << std::left << reason << count << "\n";
        }
        std::cout << "\n";
    }

    if (!app_counts.empty()) {
        std::cout << "Applications\n";
        std::cout << "------------\n";
        for (const auto& [app, count] : app_counts) {
            std::cout << std::setw(16) << std::left << appTypeToString(app) << count << "\n";
        }
        std::cout << "\n";
    }

    std::cout << "Filtered capture written to: " << options.output_file << "\n";
    return 0;
}

int runBenchmark(const CliOptions& options) {
    using clock = std::chrono::high_resolution_clock;

    uint64_t packets = 0;
    uint64_t bytes = 0;
    auto start = clock::now();

    for (int i = 0; i < options.iterations; i++) {
        CaptureSummary summary;
        if (!summarizeCapture(options.input_file, -1, summary)) {
            return 1;
        }
        packets += summary.parsed_packets;
        bytes += summary.total_bytes;
    }

    auto end = clock::now();
    std::chrono::duration<double> elapsed = end - start;
    double seconds = elapsed.count();

    std::cout << "PacketDPI Benchmark\n";
    std::cout << "===================\n\n";
    std::cout << "Input:        " << options.input_file << "\n";
    std::cout << "Iterations:   " << options.iterations << "\n";
    std::cout << "Packets:      " << packets << "\n";
    std::cout << "Bytes:        " << bytes << "\n";
    std::cout << "Elapsed:      " << std::fixed << std::setprecision(4) << seconds << " sec\n";
    std::cout << "Throughput:   "
              << (seconds > 0 ? static_cast<double>(packets) / seconds : 0.0)
              << " packets/sec\n";
    std::cout << "Data rate:    "
              << (seconds > 0 ? (static_cast<double>(bytes) / (1024.0 * 1024.0)) / seconds : 0.0)
              << " MiB/sec\n";

    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    CliOptions options;
    if (!parseArgs(argc, argv, options)) {
        printUsage(argv[0]);
        return 1;
    }

    if (options.command == "analyze" || options.command == "stats") {
        return runAnalyze(options);
    }
    if (options.command == "filter") {
        return runFilter(options);
    }
    if (options.command == "benchmark") {
        return runBenchmark(options);
    }

    printUsage(argv[0]);
    return 1;
}
