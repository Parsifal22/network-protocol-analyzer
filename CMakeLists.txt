cmake_minimum_required(VERSION 3.14)
project(network-traffic-analyzer)

# Set the build type to Release
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_CXX_STANDARD 14)



# Add source files
file(GLOB SOURCE_FILES 
    "src/*.cpp"
    "headers/*.h"
)



# Add the executable
add_executable(network-traffic-analyzer ${SOURCE_FILES})

# Set the path to Npcap installation directory
set(NPCAP_DIR "${CMAKE_CURRENT_LIST_DIR}/npcap")

# Set the path to the Npcap include directory
set(NPCAP_INCLUDE_DIR "${NPCAP_DIR}/Include")

# Set the path to the Npcap library directory
set(NPCAP_LIB_DIR "${NPCAP_DIR}/Lib/x64")

# Set the output directory for the executable
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

# Add include directories for Npcap
include_directories(${NPCAP_INCLUDE_DIR})

target_include_directories(network-traffic-analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/headers)

target_include_directories(network-traffic-analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)



# Add the HAVE_REMOTE definition for wireless devices
add_definitions(-DHAVE_REMOTE)

# Set the name of the executable
set_target_properties(network-traffic-analyzer  PROPERTIES OUTPUT_NAME trff)


# Link against Npcap library
target_link_libraries(network-traffic-analyzer PRIVATE "${NPCAP_LIB_DIR}/wpcap.lib")


