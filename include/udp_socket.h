#pragma once
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

class UdpSocket {
  public:
    UdpSocket();
    ~UdpSocket();

    void bind(const std::string& bindIp, uint16_t bindPort);
    void setNonBlocking();

    ssize_t sendTo(char* buffer, size_t bufferSize, const std::string& destIp, uint16_t destPort);

    ssize_t recvFrom(char* buffer, size_t bufferSize, std::string& srcIp, uint16_t& srcPort);

    int getFd() const;

  private:
    int socketFd;
};
