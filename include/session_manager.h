#pragma once

#include "session.h"
#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

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
    std::chrono::time_point<std::chrono::steady_clock> lastCleanUp = std::chrono::steady_clock::now();
};
