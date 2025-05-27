#include "../include/session.h"

Session::Session(const std::string& ip, uint16_t port) {
    this->deviceIp = ip;
    this->devicePort = port;
}

const std::string Session::getTunIp() const {
    return this->tunIp;
}

void Session::setTunIp(const std::string& tunIp) {
    this->deviceIp = tunIp;
}

const std::string& Session::getIp() const {
    return this->deviceIp;
}

uint16_t Session::getPort() const {
    return this->devicePort;
}

void Session::updateLastActivity() {
    this->lastActivity = std::chrono::steady_clock::now();
}

std::chrono::steady_clock::time_point Session::getLastActivity() const {
    return this->lastActivity;
}
