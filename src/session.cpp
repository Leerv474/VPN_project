#include "../include/session.h"
#include <chrono>
#include <vector>

Session::Session(const std::string& ip, uint16_t port) {
    this->deviceIp = ip;
    this->devicePort = port;
}

const std::string Session::getTunIp() const { return this->tunIp; }

void Session::setTunIp(const std::string& tunIp) { this->deviceIp = tunIp; }

const std::string& Session::getIp() const { return this->deviceIp; }

uint16_t Session::getPort() const { return this->devicePort; }

void Session::updateLastActivity() { this->lastActivity = std::chrono::steady_clock::now(); }

std::chrono::steady_clock::time_point Session::getLastActivity() const { return this->lastActivity; }

void Session::setTimeoutStamp() { this->timeoutStamp = std::chrono::steady_clock::now(); }

bool Session::isTimedOut() const {
    if (std::chrono::steady_clock::now() - this->timeoutStamp > std::chrono::seconds(5)) {
        return false;
    }
    return true;
}

bool Session::isVarified() const { return this->varified; }

void Session::setVarified(bool value) { this->varified = value; }

void Session::setChallenge(std::vector<uint8_t> challenge) { this->challenge = challenge; }

std::vector<uint8_t> Session::getChallenge() const { return this->challenge; }

void Session::setChallengedIp(std::string challengedIp) { this->challengedIp = challengedIp; }

std::string Session::getChallengedIp() const { return this->challengedIp; }
