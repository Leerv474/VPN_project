#pragma once

#include <string>
#include <chrono>

class Session {
public:
    Session(const std::string& deviceIp, uint16_t devicePort);

    const std::string getTunIp() const;
    void setTunIp(const std::string& tunIp);

    const std::string& getIp() const;
    uint16_t getPort() const;

    void updateLastActivity();
    std::chrono::steady_clock::time_point getLastActivity() const;

private:
    std::string deviceIp;
    uint16_t devicePort;
    std::string tunIp;
    std::chrono::steady_clock::time_point lastActivity;
};
