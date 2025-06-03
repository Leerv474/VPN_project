#include "../include/vpn_server.h"

VpnServer::VpnServer(const std::string& tunName, const std::string& tunIp, int tunNetmask, int port, size_t bufferSize,
                     std::map<std::string, std::string>& peersMap, const std::string& privateKey)
    : socket(), tunDevice(tunName, tunIp, tunNetmask), epollManager(), sessionManager(), buffer(bufferSize),
      bufferSize(bufferSize), payload(bufferSize), payloadSize(bufferSize), authenticator(privateKey),
      peersMap(peersMap), privateKey(privateKey) {
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

        sessionManager.removeInactiveSessions(std::chrono::seconds(900));
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
    std::vector<uint8_t> challenge;
    ssize_t nsend;

    ssize_t nrecv = socket.recvFrom(buffer.data(), buffer.size(), clientIp, clientPort);
    if (nrecv <= 0)
        return;

    if (nrecv < 20) {
        std::cerr << "Packet too small for IPv4 header\n";
        return;
    }

    MessageType type = static_cast<MessageType>(buffer[0]);
    uint32_t rawSrcIp;
    std::vector<uint8_t> ipHeader;
    if (type == MessageType::VPN_PACKET) {
        uint8_t ihl = buffer[1] & 0x0F; // IHL field is in 32-bit words
        size_t ipHeaderLen = ihl * 4;
        rawSrcIp = *reinterpret_cast<uint32_t*>(buffer.data() + 13);
        payload = std::vector(buffer.begin() + ipHeaderLen + 1, buffer.begin() + nrecv);
        ipHeader = std::vector(buffer.begin() + 1, buffer.begin() + 1 + ipHeaderLen);
    } else {
        rawSrcIp = *reinterpret_cast<uint32_t*>(buffer.data() + 1);
        payload = std::vector(buffer.begin() + 5, buffer.begin() + nrecv);
    }

    auto session = sessionManager.getOrCreateSession(rawSrcIp, clientIp, clientPort);

    bool unchallenged = !session->isVarified() && !session->isTimedOut();

    switch (type) {
    case MessageType::CLIENT_CHALLENGE:
        if (unchallenged) {
            challenge = authenticator.generateChallenge();
            session->setChallenge(challenge);
            session->setTimeoutStamp();
            challenge.insert(challenge.begin(), static_cast<uint8_t>(MessageType::SERVER_CHALLENGE));
            nsend = socket.sendTo(challenge.data(), challenge.size(), clientIp, clientPort);
            if (nsend <= 0) {
                perror("Failed to send authentication challenge");
            }
        }
        payload = authenticator.signChallenge(payload);
        payload.insert(payload.begin(), static_cast<uint8_t>(MessageType::SERVER_RESPONSE));
        socket.sendTo(payload.data(), payload.size(), clientIp, clientPort);
        break;
    case MessageType::CLIENT_RESPONSE:
        if (!authenticator.verifyChallenge(this->peersMap[session->getTunIp()], session->getChallenge(), payload)) {
            std::cerr << "Server challenge failed\n";
            session->setTimeoutStamp();
        } else {
            session->setEncryptionKey(Encryption::deriveKey(this->privateKey, this->peersMap[session->getTunIp()]));
            session->setVarified(true);
            std::cout << "Challenge succeeded\n";
        }
        break;
    case MessageType::VPN_PACKET:
        if (session->isVarified()) {
            decryptionBuffer = Encryption::decrypt(payload, session->getEncryptionKey());
            decryptionBuffer.insert(decryptionBuffer.begin(), ipHeader.begin(), ipHeader.end());
            ssize_t len = tunDevice.writePacket(decryptionBuffer.data(), nrecv);
            std::cout << "Routed packet\n";

            if (len <= 0) {
                std::cerr << "Failed to write data to tun device\n";
            }
        } else {
            buffer.clear();
            buffer.push_back(static_cast<uint8_t>(MessageType::ACCESS_DECLINED));
            ssize_t nsend = socket.sendTo(buffer.data(), 10, clientIp, clientPort);
            if (nsend <= 0) {
                std::cerr << "Failed to send data to client\n";
            }
        }
        break;
    default:
        std::cerr << "Uknown package type\n";
        break;
    }
}

void VpnServer::handleTunRead() {
    ssize_t bytes = tunDevice.readPacket(buffer.data(), buffer.size());
    if (bytes <= 0) {
        std::cerr << "Failed to read data from tun device\n";
        return;
    }

    uint32_t rawDstIp = *reinterpret_cast<uint32_t*>(buffer.data() + 16);

    auto session = sessionManager.findSessionByVpnIp(rawDstIp);
    if (!session) {
        std::cerr << "Failed to find session " << rawDstIp << " Sized at: " << bytes << '\n';
        return;
    }

    session->updateLastActivity();

    encryptionBuffer =
        Encryption::encrypt(std::vector(buffer.begin(), buffer.begin() + bytes), session->getEncryptionKey());
    encryptionBuffer.insert(encryptionBuffer.begin(), static_cast<uint8_t>(MessageType::VPN_PACKET));
    socket.sendTo(encryptionBuffer.data(), encryptionBuffer.size(), session->getIp(), session->getPort());
    std::cout << "Data send back\n";
}
