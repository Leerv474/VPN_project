#pragma once
#include "../include/vpn_tunnel.h"
#include <iostream>
#include <memory>

class VpnClient {
  public:
    VpnClient(const std::string& clientIp, const std::string& clientMask, const std::string& serverIp, int serverPort, const std::string& tunDeviceName);
    ~VpnClient();

    void runEventLoop();

  private:
    int createServerSocket(const std::string& ip, int port);
    void setNonBlocking(int fd);

    std::unique_ptr<TunDevice> tunDevice;
    int serverFd;
    const std::string tunDeviceName = "vpn";
    const int bufferSize = 2048;
};
