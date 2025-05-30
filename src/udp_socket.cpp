#include "../include/udp_socket.h"

UdpSocket::UdpSocket() {
    this->socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketFd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    int opt = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

UdpSocket::~UdpSocket() {
    if (this->socketFd >= 0) {
        close(socketFd);
    }
}

void UdpSocket::bind(const std::string& bindIp, uint16_t bindPort) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bindPort);

    if (inet_pton(AF_INET, bindIp.c_str(), &addr.sin_addr) < 0) {
        throw std::runtime_error("invalid ip address");
    }

    if (::bind(socketFd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("bind() failed");
    }

    socklen_t addrLen = sizeof(addr);
    if (getsockname(socketFd, (sockaddr*)&addr, &addrLen) == 0) {
        uint16_t assignedPort = ntohs(addr.sin_port);
        std::cout << "Socket bound to port: " << assignedPort << '\n';
    }
}

void UdpSocket::setNonBlocking() {
    int flags = fcntl(this->socketFd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        throw std::runtime_error("fcntl setup failed");
    }

    if (fcntl(this->socketFd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl set O_NONBLOCK");
        throw std::runtime_error("fcntl set O_NONBLOCK failed");
    }
}

int UdpSocket::getFd() const { return this->socketFd; }

ssize_t UdpSocket::sendTo(uint8_t* buffer, size_t bufferSize, const std::string& destIp, uint16_t destPort) {
    sockaddr_in destAddr{};
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(destPort);
    if (inet_pton(AF_INET, destIp.c_str(), &destAddr.sin_addr) < 0) {
        throw std::runtime_error("invalid destination address");
    }
    ssize_t sentBytes = sendto(socketFd, buffer, bufferSize, 0, (sockaddr*)&destAddr, sizeof(destAddr));
    if (sentBytes < 0) {
        perror("sendto() failed");
    }
    return sentBytes;
}

ssize_t UdpSocket::recvFrom(uint8_t* buffer, size_t bufferSize, std::string& srcIp, uint16_t& srcPort) {
    sockaddr_in srcAddr{};
    socklen_t addrLen = sizeof(srcAddr);

    ssize_t receivedBytes = recvfrom(socketFd, buffer, bufferSize, 0, (sockaddr*)&srcAddr, &addrLen);

    if (receivedBytes < 0) {
        perror("recvfrom() failed");
    }

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcAddr.sin_addr, ipStr, INET_ADDRSTRLEN);
    srcIp = ipStr;
    srcPort = ntohs(srcAddr.sin_port);

    return receivedBytes;
}
