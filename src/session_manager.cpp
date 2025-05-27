#include "../include/session_manager.h"

std::shared_ptr<Session> SessionManager::getOrCreateSession(uint32_t rawVpnIp, const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex);

    auto it = sessions.find(rawVpnIp);
    if (it != sessions.end()) {
        it->second->updateLastActivity();
        return it->second;
    }

    auto newSession = std::make_shared<Session>(ip, port);
    sessions[rawVpnIp] = newSession;
    std::cout << "Created new session " << rawVpnIp << ' ' << ip << ':' << port << '\n';
    return newSession;
}

std::shared_ptr<Session> SessionManager::findSessionByVpnIp(const uint32_t rawVpnIp) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = sessions.find(rawVpnIp);
    return it != sessions.end() ? it->second : nullptr;
}

void SessionManager::removeInactiveSessions(std::chrono::seconds timeout) {
    std::lock_guard<std::mutex> lock(mutex);
    auto now = std::chrono::steady_clock::now();

    for (auto it = sessions.begin(); it != sessions.end();) {
        if (now - it->second->getLastActivity() > timeout) {
            it = sessions.erase(it);
        } else {
            ++it;
        }
    }
}
