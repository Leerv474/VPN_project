cmake_minimum_required(VERSION 3.10)
project(VPN)

add_executable(vpn src/main.cpp src/vpn_tunnel.cpp src/vpn_server.cpp src/vpn_client.cpp src/cli.cpp)
# Include headers
target_include_directories(vpn PRIVATE src)

# Link necessary system libraries
target_link_libraries(vpn pthread)
