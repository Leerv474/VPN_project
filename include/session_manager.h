#pragma once

#include "session.h"
#include <cstdint>
#include <unordered_map>
#include <string>
#include <memory>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <arpa/inet.h>

class SessionManager {
public:
    std::shared_ptr<Session> getOrCreateSession(const uint32_t& rawVpnIp, const std::string& ip, uint16_t port);
    std::shared_ptr<Session> findSessionByVpnIp(const uint32_t& rawVpnIp);
    void removeInactiveSessions(std::chrono::seconds timeout);

private:
    std::string toStringRawIp(const uint32_t& rawIp);

    std::unordered_map<uint32_t, std::shared_ptr<Session>> sessions;
    std::unordered_map<uint32_t, bool> sessionStatus;
    std::mutex mutex;
};
