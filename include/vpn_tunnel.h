#pragma once
#include <iostream>

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
