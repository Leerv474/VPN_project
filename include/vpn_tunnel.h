#pragma once
#include <iostream>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>


class TunDevice {
  public:
    TunDevice(const std::string& tunName, const std::string& tunIp, const int tunNetmask);
    ~TunDevice();

    ssize_t readPacket(char* buffer, size_t bufSize);
    ssize_t writePacket(const char* buffer, size_t bufSize);
    int getFd() const;

  private:
    std::string tunName;
    int tunFd;
    std::string tunIp;
    int tunNetmask;

    bool configure(const std::string& tunIp, const int tunNetmask);
    bool removeIpTablesRules();
    std::string getDefaultInterface();
    std::string calculateNetworkAddress(const std::string& ipStr, int prefixLength);
};
