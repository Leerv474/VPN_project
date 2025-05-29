#pragma once
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <string>
#include <vector>

class Util {
  public:
    std::pair<std::string, int> splitBy(const std::string& string, const char& separator);
    std::string base64Encode(const std::vector<uint8_t>& data);
    std::pair<std::string, std::string> generateKeyPairBase64();
    void printHex(const std::vector<uint8_t>& data, const std::string& label);
};
