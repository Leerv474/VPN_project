#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

class Authenticator {
public:
    Authenticator(const std::string& privateKeyPath = "", const std::string& publicKeyPath = "");

    std::vector<uint8_t> generateChallenge(size_t size = 32);
    std::vector<uint8_t> signChallenge(const std::vector<uint8_t>& challenge);
    bool verifyChallenge(const std::vector<uint8_t>& challenge, const std::vector<uint8_t>& signature);

private:
    void loadPrivateKey(const std::string& path);
    void loadPublicKey(const std::string& path);

    EVP_PKEY* privateKey = nullptr;
    EVP_PKEY* publicKey = nullptr;
};

