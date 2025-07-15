cmake_minimum_required(VERSION 3.10)
project(ascon_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src)

# Separate C and C++ sources
file(GLOB CPP_SOURCES "src/*.cpp")
file(GLOB C_SOURCES "src/*.c")

# Declare executable with C and C++ sources
add_executable(ascon_server ${CPP_SOURCES} ${C_SOURCES})

# Ensure C linkage for C sources
set_source_files_properties(${C_SOURCES} PROPERTIES LANGUAGE C)
