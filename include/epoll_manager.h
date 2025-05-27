#pragma once

#include <sys/epoll.h>
#include <sys/types.h>
#include <vector>
#include <cstdio>
#include <stdexcept>
#include <sys/epoll.h>
#include <sys/types.h>
#include <unistd.h>

class EpollManager {
  private:
    int epollFd;

  public:
    EpollManager();
    ~EpollManager();

    void addFd(int fd, u_int32_t events);
    void modifyFd(int fd, u_int32_t events);
    void removeFd(int fd);
    int wait(epoll_event* events, int maxEvents, int timeoutMs = -1);

    int getFd() const;
};
