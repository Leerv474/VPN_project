#pragma once

#include <string>
#include <chrono>
#include <chrono>
#include <cstdint>
#include <vector>

class Session {
public:
    Session(const std::string& deviceIp, uint16_t devicePort);

    const std::string getTunIp() const;
    void setTunIp(const std::string& tunIp);

    const std::string& getIp() const;
    uint16_t getPort() const;

    void updateLastActivity();
    std::chrono::steady_clock::time_point getLastActivity() const;

    void setTimeoutStamp();
    bool isTimedOut() const;

    bool isVarified() const;
    void setVarified(bool value);

    void setChallenge(std::vector<uint8_t> challenge);
    std::vector<uint8_t> getChallenge() const;

    void setChallengedIp(std::string challengedIp);
    std::string getChallengedIp() const;

private:
    std::string deviceIp;
    uint16_t devicePort;
    std::string tunIp;
    std::chrono::steady_clock::time_point lastActivity;
    std::chrono::steady_clock::time_point timeoutStamp;
    std::vector<uint8_t> challenge;
    std::string challengedIp;
    bool varified = false;
};
