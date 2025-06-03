#pragma once

#include "authenticator.h"
#include "epoll_manager.h"
#include "message_type.h"
#include "udp_socket.h"
#include "tun_device.h"
#include "encryption.h"
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

class VpnClient {
  public:
    VpnClient(const std::string& tunName, const std::string& tunIp, const int tunNetmask, const std::string& serverIp,
              uint16_t serverPort, size_t bufferSize, const std::string& privateKey,
              const std::string& serverPublicKey);

    void eventLoop();

  private:
    void handleTunRead();
    void handleUdpRead();

    void sendChallenge();

    UdpSocket socket;
    TunDevice tunDevice;
    EpollManager epollManager;
    Authenticator authenticator;

    std::string serverIp;
    uint16_t serverPort;
    const std::string tunIp;
    const std::string serverPublicKey;
    std::vector<uint8_t> challenge;
    std::vector<uint8_t> encryptionKey;
    std::string privateKey;

    std::vector<uint8_t> buffer;
    std::vector<uint8_t> payload;
    size_t bufferSize;
    std::vector<uint8_t> decryptionBuffer;
    std::vector<uint8_t> encryptionBuffer;
    bool runEventLoop = true;
};
