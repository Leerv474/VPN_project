#pragma once
#include <iostream>
#include <string>
#include <vector>

#include "authenticator.h"
#include "epoll_manager.h"
#include "udp_socket.h"
#include "util.h"
#include "vpn_tunnel.h"
#include "message_type.h"

class VpnClient {
  public:
    VpnClient(const std::string& tunName, const std::string& tunIp, const int tunNetmask, const std::string& serverIp,
              uint16_t serverPort, size_t bufferSize, const std::string& privateKey,
              const std::string& serverPublicKey);

    void eventLoop();

  private:
    void handleRead();
    void handleSend();

    UdpSocket socket;
    TunDevice tunDevice;
    EpollManager epollManager;
    Authenticator authenticator;
    Util util;

    std::string serverIp;
    uint16_t serverPort;
    const std::string tunIp;
    const std::string serverPublicKey;
    std::vector<uint8_t> challenge;

    std::vector<uint8_t> buffer;
    size_t bufferSize;
    bool runEventLoop = true;
};
