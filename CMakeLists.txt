cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
enable_testing()

set(COMMON_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

set(DPI_ENGINE_SOURCES
    src/dpi_engine.cpp
    src/rule_manager.cpp
    src/connection_tracker.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
)

set(ANALYZER_SOURCES
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(packet_analyzer ${ANALYZER_SOURCES})

add_executable(packetdpi
    src/main_dpi.cpp
    ${COMMON_SOURCES}
    ${DPI_ENGINE_SOURCES}
)

add_executable(packetdpi_tests
    tests/unit_tests.cpp
    ${COMMON_SOURCES}
    src/rule_manager.cpp
)

target_compile_definitions(packetdpi_tests PRIVATE
    PACKETDPI_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)

add_test(NAME packetdpi_unit_tests COMMAND packetdpi_tests)
add_test(NAME packetdpi_analyze_smoke
    COMMAND packetdpi analyze "${CMAKE_CURRENT_SOURCE_DIR}/test_dpi.pcap" --max 5
)
add_test(NAME packetdpi_filter_smoke
    COMMAND packetdpi filter "${CMAKE_CURRENT_SOURCE_DIR}/test_dpi.pcap" "${CMAKE_CURRENT_BINARY_DIR}/filtered_smoke.pcap" --block-domain www.google.com
)

if(APPLE)
    target_link_libraries(packetdpi PRIVATE pthread)
    target_link_libraries(packetdpi_tests PRIVATE pthread)
endif()
