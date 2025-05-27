#include "../include/vpn_client.h"

VpnClient::VpnClient(const std::string& tunName, const std::string& tunIp, const int tunNetmask,
                     const std::string& serverIp, uint16_t serverPort, size_t bufferSize)
    : serverIp(serverIp), serverPort(serverPort), buffer(bufferSize), tunDevice(tunName, tunIp, tunNetmask) {

    socket.bind("0.0.0.0", 0);
    epollManager.addFd(tunDevice.getFd(), EPOLLIN);
    epollManager.addFd(socket.getFd(), EPOLLIN);
}

void VpnClient::eventLoop() {
    constexpr int MAX_EVENTS = 10;
    epoll_event events[MAX_EVENTS];

    while (true) {
        int n = epollManager.wait(events, MAX_EVENTS, -1);

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;

            if (fd == tunDevice.getFd()) {
                handleRead();
            } else if (fd == socket.getFd()) {
                handleSend();
            }
        }
    }
}

void VpnClient::handleRead() {
    ssize_t len = tunDevice.readPacket(buffer.data(), buffer.size());
    if (len > 0) {
        socket.sendTo(buffer.data(), len, serverIp, serverPort);
    }
    // std::cout << "[TUN] Read " << len << " bytes, sending to server " << serverIp << ":" << serverPort << std::endl;
}

void VpnClient::handleSend() {
    std::string srcIp;
    uint16_t srcPort;
    ssize_t len = socket.recvFrom(buffer.data(), buffer.size(), srcIp, srcPort);
    if (len > 0) {
        tunDevice.writePacket(buffer.data(), len);
    }
    // std::cout << "[UDP] Received " << len << " bytes from " << srcIp << ":" << srcPort << std::endl;
}
