cmake_minimum_required(VERSION 3.15)
project(packet_processor VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Check for macOS
if(APPLE)
    message(STATUS "Building for macOS")
    add_definitions(-DMACOS)
endif()

# Find libpcap
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found")
endif()

# Include directories
include_directories(
    ${PCAP_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Source files for library
set(LIB_SOURCES
    src/capture/packet_capture.cpp
    src/core/zero_copy_buffer.cpp
    src/parser/protocol_parser.cpp
)

# Create library
add_library(packet_processor SHARED ${LIB_SOURCES})

# Link with required libraries
target_link_libraries(packet_processor ${PCAP_LIBRARY})

# Set include directories for library
target_include_directories(packet_processor PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Examples
add_executable(packet_capture_example examples/packet_capture_example.cpp)
target_link_libraries(packet_capture_example packet_processor)

# Installation rules
install(TARGETS packet_processor
    EXPORT packet_processor-export
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

install(EXPORT packet_processor-export
    FILE packet_processor-config.cmake
    NAMESPACE packet_processor::
    DESTINATION lib/cmake/packet_processor
) 