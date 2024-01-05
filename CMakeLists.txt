cmake_minimum_required(VERSION 3.14)
project(network-protocol-analyzer)

set(CMAKE_CXX_STANDARD 14)


# Add source files
file(GLOB SOURCE_FILES 
    "src/*.cpp"
    "headers/*.h"
)


# Add the executable
add_executable(network-protocol-analyzer ${SOURCE_FILES})

# Set the path to Npcap installation directory
set(NPCAP_DIR "${CMAKE_CURRENT_LIST_DIR}/npcap")

# Set the path to the Npcap include directory
set(NPCAP_INCLUDE_DIR "${NPCAP_DIR}/Include")

# Set the path to the Npcap library directory
set(NPCAP_LIB_DIR "${NPCAP_DIR}/Lib/x64")

# Add include directories for Npcap
include_directories(${NPCAP_INCLUDE_DIR})

target_include_directories(network-protocol-analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/headers)

target_include_directories(network-protocol-analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Add the HAVE_REMOTE definition
add_definitions(-DHAVE_REMOTE)

# Link against Npcap library
target_link_libraries(network-protocol-analyzer PRIVATE "${NPCAP_LIB_DIR}/wpcap.lib")


