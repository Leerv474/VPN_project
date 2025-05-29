#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

class Authenticator {
  public:
    Authenticator(const std::string& privateKey);
    ~Authenticator();

    std::vector<uint8_t> generateChallenge(size_t size = 32);
    std::vector<uint8_t> signChallenge(const std::vector<uint8_t>& challenge);
    bool verifyChallenge(const std::string& publicKeyPem, const std::vector<uint8_t>& challenge,
                         const std::vector<uint8_t>& signature);

  private:
    std::vector<uint8_t> base64Decode(const std::string& base64);
    void loadPrivateKey(const std::string& privateKey);
    EVP_PKEY* loadPublicKey(const std::string& publicKey);

    EVP_PKEY* privateKey = nullptr;
};
