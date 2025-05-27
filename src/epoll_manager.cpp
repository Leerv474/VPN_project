#include "../include/epoll_manager.h"

EpollManager::EpollManager() {
    this->epollFd = epoll_create1(0);
    if (epollFd == -1) {
        throw std::runtime_error("Failed to create epoll instance");
    }
}

EpollManager::~EpollManager() {
    if (this->epollFd != -1) {
        close(this->epollFd);
    }
}

void EpollManager::addFd(int fd, u_int32_t events) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        perror("Failed to add fd to epoll");
    }
}

void EpollManager::modifyFd(int fd, u_int32_t events) {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(this->epollFd, EPOLL_CTL_MOD, fd, &ev) == -1) {
        perror("Failed to modify fd in epoll");
    }
}

void EpollManager::removeFd(int fd) {
    if (epoll_ctl(this->epollFd, EPOLL_CTL_DEL, fd, nullptr) == -1) {
        perror("Failed to remove fd from epoll");
    }
}

int EpollManager::wait(epoll_event* events, int maxEvents, int timeoutMs) {
    int n = epoll_wait(this->epollFd, events, maxEvents, timeoutMs);
    if (n < 0) {
        perror("epoll_wait failed");
    }
    return n;
}

int EpollManager::getFd() const { return this->epollFd; }
