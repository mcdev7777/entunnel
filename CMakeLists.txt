cmake_minimum_required(VERSION 4.1)
project(entunnel)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_definitions(-DSECURITY_WIN32)
add_link_options(-fuse-ld=lld)

add_executable(entunnel main.cpp)

target_sources(entunnel PRIVATE
        FILE_SET module_files TYPE CXX_MODULES FILES
        src/proxy/proxy_resolver.ixx
        src/inet/tcp_tunnel.ixx
        src/inet/scoped_socket.ixx
        src/http/http_parser.ixx
        src/sspi/sspi_authenticate.ixx
        src/encoding/base64.ixx
        src/entunnel.ixx
        src/encoding/string.ixx
)

target_include_directories(entunnel PUBLIC
        "."
        "src/"
)

target_link_libraries(entunnel PRIVATE winhttp ws2_32 secur32 crypt32)

