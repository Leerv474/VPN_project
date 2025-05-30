#pragma once
#include <iomanip>
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
    static std::pair<std::string, int> splitBy(const std::string& string, const char& separator);
    static std::pair<std::string, std::string> generateKeyPairBase64();
    static void printHex(const std::vector<uint8_t>& data, const std::string& label);

    static std::vector<uint8_t> base64Decode(const std::string& base64);

  private:
    static std::string base64Encode(const std::vector<uint8_t>& data);
};
