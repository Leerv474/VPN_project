#pragma once
#include "../include/epoll_manager.h"
#include "../include/message_type.h"
#include "../include/session_manager.h"
#include "../include/udp_socket.h"
#include "../include/vpn_tunnel.h"
#include "authenticator.h"
#include "util.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <sys/types.h>
#include <vector>

class VpnServer {
  public:
    VpnServer(const std::string& tunName, const std::string& tunIp, const int tunNetmask, int port, size_t bufferSize,
              std::map<std::string, std::string>& peersMap, const std::string& privateKey);
    ~VpnServer();

    VpnServer(const VpnServer&) = delete;
    VpnServer& operator=(const VpnServer&) = delete;
    VpnServer(VpnServer&&) = default;
    VpnServer& operator=(VpnServer&&) = default;

    void start();
    void stop();

  private:
    void eventLoop();
    void handleTunRead();
    void handleUdpRead();
    void acceptClient();

    UdpSocket socket;
    TunDevice tunDevice;
    EpollManager epollManager;
    SessionManager sessionManager;
    Authenticator authenticator;
    Util util;

    std::map<std::string, std::string> peersMap;

    std::vector<uint8_t> buffer;
    size_t bufferSize;

    std::vector<uint8_t> payload;
    size_t payloadSize;

    bool keepAlive = false;
};
