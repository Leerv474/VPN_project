#include "../include/vpn_client.h"

VpnClient::VpnClient(const std::string& tunName, const std::string& tunIp, const int tunNetmask,
                     const std::string& serverIp, uint16_t serverPort, size_t bufferSize, const std::string& privateKey,
                     const std::string& serverPublicKey)
    : serverIp(serverIp), serverPort(serverPort), buffer(bufferSize), bufferSize(bufferSize),
      tunDevice(tunName, tunIp, tunNetmask), serverPublicKey(serverPublicKey), authenticator(privateKey),
      privateKey(privateKey), tunIp(tunIp) {

    socket.bind("0.0.0.0", 0);
    epollManager.addFd(tunDevice.getFd(), EPOLLIN);
    epollManager.addFd(socket.getFd(), EPOLLIN);
}

void VpnClient::eventLoop() {
    constexpr int MAX_EVENTS = 10;
    epoll_event events[MAX_EVENTS];

    std::this_thread::sleep_for(std::chrono::seconds(1));

    std::vector<uint8_t> generatedChallenge = authenticator.generateChallenge();
    this->challenge = generatedChallenge;
    uint32_t vpnIp = inet_addr(this->tunIp.c_str());
    generatedChallenge.insert(generatedChallenge.begin(), reinterpret_cast<uint8_t*>(&vpnIp),
                              reinterpret_cast<uint8_t*>(&vpnIp) + sizeof(vpnIp));
    generatedChallenge.insert(generatedChallenge.begin(), static_cast<uint8_t>(MessageType::CLIENT_CHALLENGE));
    ssize_t nsend =
        socket.sendTo(generatedChallenge.data(), generatedChallenge.size(), this->serverIp, this->serverPort);

    if (nsend <= 0) {
        std::runtime_error("Failed to send authentication challenge");
    }

    while (runEventLoop) {
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
        uint8_t ihl = buffer[0] & 0x0F; // IHL field is in 32-bit words
        size_t ipHeaderLen = ihl * 4;

        std::vector<uint8_t> ipHeader(buffer.begin(), buffer.begin() + ipHeaderLen);
        std::vector<uint8_t> payload(buffer.begin() + ipHeaderLen, buffer.begin() + len);

        // Encrypt payload
        std::vector<uint8_t> encryptedPayload = Encryption::encrypt(payload, encryptionKey);

        // Compose final buffer
        std::vector<uint8_t> packet;
        packet.push_back(static_cast<uint8_t>(MessageType::VPN_PACKET));
        packet.insert(packet.end(), ipHeader.begin(), ipHeader.end());
        packet.insert(packet.end(), encryptedPayload.begin(), encryptedPayload.end());
        ssize_t nsend = socket.sendTo(packet.data(), packet.size(), serverIp, serverPort);
        std::cout << "Data sent\n";
    }
}

void VpnClient::handleSend() {
    std::string srcIp;
    uint16_t srcPort;
    buffer.resize(bufferSize);
    ssize_t nrecv = socket.recvFrom(buffer.data(), buffer.size(), srcIp, srcPort);
    uint32_t vpnIp;
    ssize_t len;
    std::vector<uint8_t> decryptedPayload;
    if (nrecv > 0) {
        MessageType type = static_cast<MessageType>(buffer[0]);
        std::vector<uint8_t> payload(buffer.begin() + 1, buffer.begin() + nrecv);

        switch (type) {
        case MessageType::SERVER_RESPONSE:
            if (!authenticator.verifyChallenge(serverPublicKey, this->challenge, payload)) {
                std::cout << serverPublicKey << '\n';
                throw std::runtime_error("Client challenge failed");
            }
            std::cout << "Challenge succeeded\n";
            this->encryptionKey = Encryption::deriveKey(this->privateKey, this->serverPublicKey);
            break;
        case MessageType::SERVER_CHALLENGE:
            buffer = authenticator.signChallenge(payload);
            vpnIp = inet_addr(this->tunIp.c_str());
            buffer.insert(buffer.begin(), reinterpret_cast<uint8_t*>(&vpnIp),
                          reinterpret_cast<uint8_t*>(&vpnIp) + sizeof(vpnIp));
            buffer.insert(buffer.begin(), static_cast<uint8_t>(MessageType::CLIENT_RESPONSE));
            socket.sendTo(buffer.data(), buffer.size(), this->serverIp, this->serverPort);
            break;
        case MessageType::VPN_PACKET:
            decryptedPayload = Encryption::decrypt(payload, this->encryptionKey);
            tunDevice.writePacket(decryptedPayload.data(), nrecv - 1);
            if (len <= 0) {
                std::cout << "Failed to write data to TUN\n";
            }
            break;
        default:
            std::cout << "Unknown package type\n";
            break;
        }
    }
}
