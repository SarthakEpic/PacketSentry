#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "packet_parser.h"
#include "pcap_reader.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include "types.h"

using namespace DPI;
using namespace PacketAnalyzer;

namespace {

std::vector<uint8_t> makeTLSClientHello(const std::string& hostname) {
    std::vector<uint8_t> body;

    body.push_back(0x03);
    body.push_back(0x03);
    body.insert(body.end(), 32, 0x11);
    body.push_back(0x00);
    body.push_back(0x00);
    body.push_back(0x02);
    body.push_back(0x00);
    body.push_back(0x2f);
    body.push_back(0x01);
    body.push_back(0x00);

    uint16_t sni_length = static_cast<uint16_t>(hostname.size());
    uint16_t sni_list_length = static_cast<uint16_t>(1 + 2 + sni_length);
    uint16_t sni_extension_length = static_cast<uint16_t>(2 + sni_list_length);
    uint16_t extensions_length = static_cast<uint16_t>(4 + sni_extension_length);

    body.push_back(static_cast<uint8_t>(extensions_length >> 8));
    body.push_back(static_cast<uint8_t>(extensions_length & 0xff));
    body.push_back(0x00);
    body.push_back(0x00);
    body.push_back(static_cast<uint8_t>(sni_extension_length >> 8));
    body.push_back(static_cast<uint8_t>(sni_extension_length & 0xff));
    body.push_back(static_cast<uint8_t>(sni_list_length >> 8));
    body.push_back(static_cast<uint8_t>(sni_list_length & 0xff));
    body.push_back(0x00);
    body.push_back(static_cast<uint8_t>(sni_length >> 8));
    body.push_back(static_cast<uint8_t>(sni_length & 0xff));
    body.insert(body.end(), hostname.begin(), hostname.end());

    uint32_t handshake_length = static_cast<uint32_t>(body.size());
    uint16_t record_length = static_cast<uint16_t>(4 + body.size());

    std::vector<uint8_t> record;
    record.push_back(0x16);
    record.push_back(0x03);
    record.push_back(0x03);
    record.push_back(static_cast<uint8_t>(record_length >> 8));
    record.push_back(static_cast<uint8_t>(record_length & 0xff));
    record.push_back(0x01);
    record.push_back(static_cast<uint8_t>((handshake_length >> 16) & 0xff));
    record.push_back(static_cast<uint8_t>((handshake_length >> 8) & 0xff));
    record.push_back(static_cast<uint8_t>(handshake_length & 0xff));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

void testTLSExtractor() {
    auto hello = makeTLSClientHello("www.youtube.com");
    assert(SNIExtractor::isTLSClientHello(hello.data(), hello.size()));
    auto sni = SNIExtractor::extract(hello.data(), hello.size());
    assert(sni);
    assert(*sni == "www.youtube.com");

    auto extensions = SNIExtractor::extractExtensions(hello.data(), hello.size());
    assert(!extensions.empty());
    assert(extensions[0].first == 0);
    assert(extensions[0].second == "www.youtube.com");
}

void testHTTPHostExtractor() {
    const std::string request =
        "GET /watch HTTP/1.1\r\n"
        "Host: Example.COM:443\r\n"
        "User-Agent: PacketDPI-Test\r\n\r\n";
    auto host = HTTPHostExtractor::extract(
        reinterpret_cast<const uint8_t*>(request.data()), request.size());
    assert(host);
    assert(*host == "Example.COM");
}

void testDNSExtractor() {
    std::vector<uint8_t> dns = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    auto query = DNSExtractor::extractQuery(dns.data(), dns.size());
    assert(query);
    assert(*query == "example.com");
}

void testRuleManager() {
    RuleManager rules;
    rules.blockDomain("*.YouTube.com");
    assert(rules.isDomainBlocked("music.youtube.com"));
    assert(rules.isDomainBlocked("youtube.com"));
    assert(!rules.isDomainBlocked("example.com"));

    rules.blockPort(443);
    assert(rules.isPortBlocked(443));
    assert(!rules.isPortBlocked(80));
}

void testAppMapping() {
    assert(sniToAppType("www.youtube.com") == AppType::YOUTUBE);
    assert(sniToAppType("api.github.com") == AppType::GITHUB);
    assert(sniToAppType("mail.google.com") == AppType::GOOGLE);
    assert(sniToAppType("www.netflix.com") == AppType::NETFLIX);
    assert(sniToAppType("www.microsoft.com") == AppType::MICROSOFT);
    assert(sniToAppType("api.x.com") == AppType::TWITTER);
}

void testSamplePcap() {
    std::string pcap = std::string(PACKETDPI_TEST_DATA_DIR) + "/test_dpi.pcap";
    PcapReader reader;
    assert(reader.open(pcap));

    RawPacket raw;
    ParsedPacket parsed;
    assert(reader.readNextPacket(raw));
    assert(PacketParser::parse(raw, parsed));
    assert(parsed.has_ip);
    assert(parsed.has_tcp);
    assert(parsed.dest_port == 443);
    reader.close();
}

} // namespace

int main() {
    testTLSExtractor();
    testHTTPHostExtractor();
    testDNSExtractor();
    testRuleManager();
    testAppMapping();
    testSamplePcap();

    std::cout << "packetdpi unit tests passed\n";
    return 0;
}
