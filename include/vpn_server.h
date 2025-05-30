#pragma once
#include "authenticator.h"
#include "epoll_manager.h"
#include "message_type.h"
#include "session_manager.h"
#include "udp_socket.h"
#include "vpn_tunnel.h"
#include "encryption.h"
#include <arpa/inet.h>
#include <cstdint>
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
    std::string toStringRawIp(const uint32_t& rawIp);

    UdpSocket socket;
    TunDevice tunDevice;
    EpollManager epollManager;
    SessionManager sessionManager;
    Authenticator authenticator;

    std::string privateKey;
    std::map<std::string, std::string> peersMap;

    std::vector<uint8_t> buffer;
    size_t bufferSize;

    std::vector<uint8_t> payload;
    size_t payloadSize;

    bool keepAlive = false;
};
