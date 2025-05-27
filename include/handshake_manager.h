#pragma once
#include <cstdint>
#include <iostream>
#include <vector>

class HandshakeManager {
public:
    std::vector<uint8_t> initiateHandshake(const std::string& clientPrivateKey, const std::string& serverPublicKey);
    bool verifyHandshake(const std::string& receivedSignature, const std::string& publicKey, const std::string& challenge);
    std::string signChallenge(const std::string& privateKey, const std::string& challenge);
    std::string generateChallenge();
};
