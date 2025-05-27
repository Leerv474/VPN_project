#include "../include/vpn_server.h"

VpnServer::VpnServer(const std::string& tunName, const std::string& tunIp, int tunNetmask, int port, size_t bufferSize,
                     std::map<std::string, std::string>& peersMap, std::string privateKey)
    : socket(), tunDevice(tunName, tunIp, tunNetmask), epollManager(), sessionManager(), buffer(bufferSize),
      bufferSize(bufferSize) {
    socket.bind("0.0.0.0", port);
    socket.setNonBlocking();

    epollManager.addFd(socket.getFd(), EPOLLIN);
    epollManager.addFd(tunDevice.getFd(), EPOLLIN);
}

VpnServer::~VpnServer() { stop(); }

void VpnServer::start() {
    keepAlive = true;
    eventLoop();
}

void VpnServer::stop() { keepAlive = false; }

void VpnServer::eventLoop() {
    constexpr int MAX_EVENTS = 10;
    epoll_event events[MAX_EVENTS];

    while (keepAlive) {
        int n = epollManager.wait(events, MAX_EVENTS, -1);

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;

            if (fd == tunDevice.getFd()) {
                handleTunRead();
            } else if (fd == socket.getFd()) {
                handleUdpRead();
            }
        }
    }
}

void VpnServer::handleUdpRead() {
    std::string clientIp;
    uint16_t clientPort;
    ssize_t bytes = socket.recvFrom(buffer.data(), bufferSize, clientIp, clientPort);
    if (bytes <= 0)
        return;

    if (bytes < 20) {
        std::cerr << "Packet too small for IPv4 header\n";
        return;
    }

    uint32_t rawSrcIp = *reinterpret_cast<uint32_t*>(buffer.data() + 12); // IPv4 dst field
    auto session = sessionManager.getOrCreateSession(rawSrcIp, clientIp, clientPort);

    session->updateLastActivity();

    // Decrypt here if needed (stub for now)

    tunDevice.writePacket(buffer.data(), bytes);
}

void VpnServer::handleTunRead() {
    ssize_t bytes = tunDevice.readPacket(buffer.data(), bufferSize);
    if (bytes <= 0)
        return;

    uint32_t rawDstIp = *reinterpret_cast<uint32_t*>(buffer.data() + 16); // IPv4 dst field

    auto session = sessionManager.findSessionByVpnIp(rawDstIp);
    if (!session) {
        std::cout << "Failed to find session " << rawDstIp << " Sized at: " << bytes << '\n';
        return;
    }

    session->updateLastActivity();

    // Encrypt here if needed (stub for now)

    socket.sendTo(buffer.data(), bytes, session->getIp(), session->getPort());
}
