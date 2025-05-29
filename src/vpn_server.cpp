#include "../include/vpn_server.h"
#include <cstdint>
#include <iomanip>
#include <sys/types.h>
#include <vector>

VpnServer::VpnServer(const std::string& tunName, const std::string& tunIp, int tunNetmask, int port, size_t bufferSize,
                     std::map<std::string, std::string>& peersMap, const std::string& privateKey)
    : socket(), tunDevice(tunName, tunIp, tunNetmask), epollManager(), sessionManager(), buffer(bufferSize),
      bufferSize(bufferSize), payload(bufferSize), payloadSize(bufferSize), authenticator(privateKey),
      peersMap(peersMap) {
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
    ssize_t nrecv = socket.recvFrom(buffer.data(), bufferSize, clientIp, clientPort);
    if (nrecv <= 0)
        return;

    if (nrecv < 20) {
        std::cerr << "Packet too small for IPv4 header\n";
        return;
    }

    MessageType type = static_cast<MessageType>(buffer[0]);
    uint32_t rawSrcIp;
    if (type == MessageType::VPN_PACKET) {
        rawSrcIp = *reinterpret_cast<uint32_t*>(buffer.data() + 13);
        payload = std::vector(buffer.begin() + 1, buffer.begin() + nrecv);
    } else {
        rawSrcIp = *reinterpret_cast<uint32_t*>(buffer.data() + 1);
        payload = std::vector(buffer.begin() + 5, buffer.begin() + nrecv);
    }

    auto session = sessionManager.getOrCreateSession(rawSrcIp, clientIp, clientPort);

    struct in_addr ip_addr;
    ip_addr.s_addr = rawSrcIp;

    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);
    std::string ipStr(str);

    std::vector<uint8_t> challenge;
    ssize_t nsend;

    bool unchallenged = !session->isVarified() && !session->isTimedOut() && session->getChallenge().empty();
    if (type == MessageType::CLIENT_CHALLENGE) {
        challenge = authenticator.generateChallenge();
        session->setChallenge(challenge);
        session->setTimeoutStamp();
        session->setChallengedIp(ipStr);
        challenge.insert(challenge.begin(), static_cast<uint8_t>(MessageType::SERVER_CHALLENGE));
        nsend = socket.sendTo(challenge.data(), challenge.size(), clientIp, clientPort);
        if (nsend <= 0) {
            perror("Failed to send authentication challenge");
        }
    }

    switch (type) {
    case MessageType::CLIENT_CHALLENGE:
        payload = authenticator.signChallenge(payload);
        payload.insert(payload.begin(), static_cast<uint8_t>(MessageType::SERVER_RESPONSE));
        socket.sendTo(payload.data(), payload.size(), clientIp, clientPort);
        break;
    case MessageType::CLIENT_RESPONSE:
        if (!authenticator.verifyChallenge(this->peersMap[session->getChallengedIp()], session->getChallenge(),
                                           payload)) {
            std::cout << "Server challenge failed\n";
            std::cout << this->peersMap[session->getChallengedIp()] << '\n';
            session->setTimeoutStamp();
        } else {
            session->setVarified(true);
            std::cout << "Challenge succeeded\n";
        }
        break;
    case MessageType::VPN_PACKET:
        if (session->isVarified()) {
            ssize_t len = tunDevice.writePacket(payload.data(), nrecv - 1);

            uint16_t totalLength = ntohs(*reinterpret_cast<uint16_t*>(payload.data() + 2));
            if (len <= 0) {
                std::cout << "Failed to write data to tun device\n";
            }
        }
        break;
    default:
        std::cout << "Uknown package type\n";
        break;
    }
}

void VpnServer::handleTunRead() {
    ssize_t bytes = tunDevice.readPacket(buffer.data(), buffer.size());
    if (bytes <= 0) {
        std::cout << "Failed to read data from tun device\n";
        return;
    }

    uint32_t rawDstIp = *reinterpret_cast<uint32_t*>(buffer.data() + 16);

    auto session = sessionManager.findSessionByVpnIp(rawDstIp);
    if (!session) {
        std::cout << "Failed to find session " << rawDstIp << " Sized at: " << bytes << '\n';
        return;
    }

    session->updateLastActivity();

    buffer.insert(buffer.begin(), static_cast<uint8_t>(MessageType::VPN_PACKET));
    socket.sendTo(buffer.data(), bytes + 1, session->getIp(), session->getPort());
}
