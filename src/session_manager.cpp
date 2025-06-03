#include "../include/session_manager.h"

std::shared_ptr<Session> SessionManager::getOrCreateSession(const uint32_t& rawVpnIp, const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex);

    auto it = sessions.find(rawVpnIp);
    if (it != sessions.end()) {
        it->second->updateLastActivity();
        return it->second;
    }

    auto newSession = std::make_shared<Session>(ip, port, toStringRawIp(rawVpnIp));
    sessions[rawVpnIp] = newSession;
    return newSession;
}
std::shared_ptr<Session> SessionManager::findSessionByVpnIp(const uint32_t& rawVpnIp) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = sessions.find(rawVpnIp);
    return it != sessions.end() ? it->second : nullptr;
}

void SessionManager::removeInactiveSessions(std::chrono::seconds timeout) {
    auto now = std::chrono::steady_clock::now();
    if (now - lastCleanUp <= std::chrono::seconds(900)) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex);

    for (auto it = sessions.begin(); it != sessions.end();) {
        if (now - it->second->getLastActivity() > timeout) {
            it = sessions.erase(it);
        } else {
            ++it;
        }
    }
}

std::string SessionManager::toStringRawIp(const uint32_t& rawIp) {
    struct in_addr ip_addr;
    ip_addr.s_addr = rawIp;

    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, str, INET_ADDRSTRLEN);
    return std::string(str);
}

