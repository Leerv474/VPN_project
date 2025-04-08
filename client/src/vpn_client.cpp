#include "../include/vpn_client.h"

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

VpnClient::VpnClient(const std::string& clientIp, const std::string& clientMask, const std::string& serverIp, int serverPort,
                     const std::string& tunDeviceName) {
    this->tunDevice = std::make_unique<TunDevice>(tunDeviceName, clientIp, clientMask, this->tunDeviceName);
    this->serverFd = createServerSocket(serverIp, serverPort);
    setNonBlocking(this->tunDevice->getFd());
    setNonBlocking(this->serverFd);
}

VpnClient::~VpnClient() = default;

int VpnClient::createServerSocket(const std::string& ip, int port) {
    int sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) {
        perror("Socket creation failed");
        throw std::runtime_error("Failed to create server socket");
    }

    setNonBlocking(sockFd);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr) <= 0) {
        perror("Invalid ip");
        close(sockFd);
        throw std::runtime_error("Invalid server ip address");
    }

    if (connect(sockFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("Connection failed");
            close(sockFd);
            throw std::runtime_error("Failed to connect to the server");
        }
    }

    return sockFd;
}

void VpnClient::setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        throw std::runtime_error("fcntl setup failed");
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl set O_NONBLOCK");
        throw std::runtime_error("fcntl set O_NONBLOCK failed");
    }
}

void VpnClient::runEventLoop() {
    int epollFd = epoll_create1(0);
    if (epollFd == -1) {
        perror("epoll_create1");
        throw std::runtime_error("epoll_ctl creation failed");
    }

    struct epoll_event tunEv;
    tunEv.events = EPOLLIN;
    tunEv.data.fd = this->tunDevice->getFd();
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, this->tunDevice->getFd(), &tunEv) == -1) {
        perror("epoll_ctl tunFd");
        close(epollFd);
        throw std::runtime_error("epoll_ctl tunFd failed");
    }

    struct epoll_event serverEv;
    serverEv.data.fd = serverFd;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, serverFd, &serverEv) == -1) {
        perror("epoll_ctl serverFd");
        close(epollFd);
        throw std::runtime_error("epoll_ctl serverFd failed");
    }

    char buffer[this->bufferSize];
    bool keep_alive = true;
    while (keep_alive) {
        struct epoll_event events[2];
        int nfds = epoll_wait(epollFd, events, 2, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            keep_alive = false;
            break;
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == this->tunDevice->getFd()) {
                ssize_t nread = read(this->tunDevice->getFd(), buffer, bufferSize);
                if (nread > 0) {
                    ssize_t nsend = send(serverFd, buffer, nread, 0);
                    if (nsend == -1) {
                        perror("send failed");
                        continue;
                    }
                } else {
                    perror("read failed");
                    continue;
                }
            } else if (events[i].data.fd == serverFd) {
                ssize_t nrecv = recv(serverFd, buffer, bufferSize, 0);
                if (nrecv > 0) {
                    ssize_t nwrite = write(this->tunDevice->getFd(), buffer, nrecv);
                    if (nwrite == -1) {
                        perror("write failed");
                        continue;
                    }
                } else if (nrecv == 0) {
                    perror("server closed connection");
                    continue;
                } else {
                    perror("recv failed");
                    continue;
                }
            }
        }
    }

    close(epollFd);
}
