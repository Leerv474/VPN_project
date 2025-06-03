cmake_minimum_required(VERSION 3.14)
project(VPN)

set(CMAKE_CXX_STANDARD 17)

find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

# Use pkg-config to find sodium
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(vpn
    src/main.cpp
    src/tun_device.cpp
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
    src/encryption.cpp
)

target_include_directories(vpn PRIVATE src ${SODIUM_INCLUDE_DIRS})
target_link_libraries(vpn PRIVATE nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto ${SODIUM_LIBRARIES})

# Add compiler flags from pkg-config
target_compile_options(vpn PRIVATE ${SODIUM_CFLAGS_OTHER})

