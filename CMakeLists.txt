cmake_minimum_required(VERSION 3.14)
project(VPN)

set(CMAKE_CXX_STANDARD 17)

find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(vpn
    src/main.cpp
    src/vpn_tunnel.cpp
    src/vpn_server.cpp
    src/vpn_client.cpp
    src/udp_socket.cpp
    src/session.cpp
    src/session_manager.cpp
    src/epoll_manager.cpp
    src/cli.cpp
    src/configuration_parser.cpp
    src/util.cpp
    src/authenticator.cpp
)

target_include_directories(vpn PRIVATE src)
target_link_libraries(vpn PRIVATE nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)
