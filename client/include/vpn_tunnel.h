#include <iostream>

class TunDevice {
  public:
    TunDevice(const std::string& devName, const std::string& deviceIp, const std::string& netmask,
              const std::string& networkDevice);
    ~TunDevice();

    ssize_t readPacket(char* buffer, size_t bufSize);
    ssize_t writePacket(const char* buffer, size_t bufSize);
    int getFd() const;

  private:
    std::string deviceName;
    int tunFd;
    std::string deviceIp;

    bool configure(const std::string& deviceIp, const std::string& netmask, const std::string& networkDevice);
};
