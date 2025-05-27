#pragma once
#include <iostream>
#include <string>
#include <vector>

#include "epoll_manager.h"
#include "udp_socket.h"
#include "vpn_tunnel.h"

class VpnClient {
  public:
    VpnClient(const std::string& tunName, const std::string& tunIp, const int tunNetmask,
              const std::string& serverIp, uint16_t serverPort, size_t bufferSize);

    void eventLoop();
  private:

    void handleRead();
    void handleSend();

    UdpSocket socket;
    TunDevice tunDevice;
    EpollManager epollManager;

    std::string serverIp;
    uint16_t serverPort;

    std::vector<char> buffer;
};
