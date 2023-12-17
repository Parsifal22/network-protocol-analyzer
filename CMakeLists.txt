cmake_minimum_required(VERSION 3.14)
project(network-protocol-analyzer)

set(CMAKE_CXX_STANDARD 14)


# Add your source files
set(SOURCE_FILES main.cpp)


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


# Link against Npcap library
target_link_libraries(network-protocol-analyzer PRIVATE "${NPCAP_LIB_DIR}/wpcap.lib")


