#include "../include/vpn_server.h"
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

VpnServer::VpnServer(const std::string& tunName, int port, size_t bufferSize) {
    this->tunName = tunName;
    this->port = port;
    this->bufferSize = bufferSize;
    this->buffer = std::make_unique<char[]>(bufferSize);
    this->keepAlive = true;
}

VpnServer::~VpnServer() {
    if (this->tunFd != -1) {
        close(this->tunFd);
        this->tunFd = -1;
    }
    if (this->serverSocketFd != -1) {
        close(this->serverSocketFd);
    }
    if (this->clientFd != -1) {
        close(this->clientFd);
    }
    if (this->epollFd != -1) {
        close(this->epollFd);
    }
}

void VpnServer::stop() {
    this->keepAlive = false;
    if (this->tunFd != -1) {
        close(this->tunFd);
    }
    if (this->serverSocketFd != -1) {
        close(this->serverSocketFd);
    }
    if (this->clientFd != -1) {
        close(this->clientFd);
    }
    if (this->epollFd != -1) {
        close(this->epollFd);
    }
}

void VpnServer::setupTun() {
    struct ifreq ifr = {};
    this->tunFd = open("/dev/net/tun", O_RDWR);
    if (this->tunFd < 0) {
        perror("Failed to open tun interface");
        throw std::runtime_error("Cannot open /dev/net/tun");
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, tunName.c_str(), IFNAMSIZ);

    if (ioctl(this->tunFd, TUNSETIFF, &ifr) < 0) {
        close(this->tunFd);
        this->tunFd = -1;
        perror("Failed to configure TUN device");
        throw std::runtime_error("Failed to configure TUN device");
    }
    fcntl(this->tunFd, F_SETFL, fcntl(this->tunFd, F_GETFL, 0) | O_NONBLOCK);
}

void VpnServer::setupServerSocket() {
    this->serverSocketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->serverSocketFd < 0) {
        perror("Failed to create socket");
        throw std::runtime_error("Failed to create socket");
    }

    int opt = -1;
    setsockopt(this->serverSocketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(this->serverSocketFd, (sockaddr*)&addr, sizeof(addr)) < 0 || listen(this->serverSocketFd, 1) < 0) {
        close(this->serverSocketFd);
        perror("Failed to bind or listen");
        throw std::runtime_error("Failed to bind or listen");
    }
}

void VpnServer::acceptClient() {
    sockaddr_in clientAddr = {};
    socklen_t len = sizeof(clientAddr);
    this->clientFd = accept(this->serverSocketFd, (sockaddr*)&clientAddr, &len);
    if (this->clientFd < 0) {
        perror("Failed to accept client");
        throw std::runtime_error("Failed to accept client");
    }
    fcntl(this->clientFd, F_SETFL, fcntl(this->clientFd, F_GETFL, 0) | O_NONBLOCK);
}

void VpnServer::eventLoop() {
    this->epollFd = epoll_create1(0);
    if (this->epollFd < 0) {
        perror("Failed to create epoll instance");
        throw std::runtime_error("Failed to create epoll instance");
    }

    epoll_event serverEv = {EPOLLIN, {.fd = this->tunFd}};
    epoll_event clientEv = {EPOLLIN | EPOLLRDHUP, {.fd = this->clientFd}};

    if (epoll_ctl(this->epollFd, EPOLL_CTL_ADD, this->tunFd, &serverEv) < 0 ||
        epoll_ctl(this->epollFd, EPOLL_CTL_ADD, this->clientFd, &clientEv) < 0) {
        perror("Failed to add file descriptors to epoll");
        throw std::runtime_error("Failed to add file descriptors to epoll");
    }

    while (this->keepAlive) {
        epoll_event events[2];
        int nfds = epoll_wait(this->epollFd, events, 2, -1);
        if (nfds < 0) {
            perror("epoll_wait");
            continue;
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == this->tunFd) {
                ssize_t nread = read(this->tunFd, this->buffer.get(), this->bufferSize);
                if (nread > 0) {
                    if (send(this->clientFd, this->buffer.get(), nread, 0) < 0) {
                        perror("send to client");
                    }
                } else {
                    perror("read from tun");
                }
            } else if (events[i].data.fd == this->clientFd) {
                if (events[i].events & EPOLLRDHUP) {
                    perror("client disconnected");
                    this->keepAlive = false;
                    break;
                }
                ssize_t nrecv = recv(this->clientFd, this->buffer.get(), this->bufferSize, 0);
                if (nrecv > 0) {
                    if (write(this->tunFd, this->buffer.get(), nrecv) < 0) {
                        perror("write to tun");
                    }
                } else if (nrecv == 0) {
                    perror("client disconnected");
                    this->keepAlive = false;
                } else {
                    perror("recv from client");
                }
            }
        }
    }
}
