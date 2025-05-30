#pragma once

#include "util.h"
#include <cstdint>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <string>
#include <vector>

class Encryption {
  public:
    static std::vector<uint8_t> deriveKey(const std::string& privateKey, const std::string& publicKey);
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

  private:
    static std::vector<uint8_t> ed25519PrivToX25519(const std::vector<uint8_t>& edPriv);
    static std::vector<uint8_t> ed25519PubToX25519(const std::vector<uint8_t>& edPub);
    static std::vector<uint8_t> x25519ECDH(const std::vector<uint8_t>& x25519Priv,
                                           const std::vector<uint8_t>& x25519Pub);
    static std::vector<uint8_t> hkdfSha256(const std::vector<uint8_t>& ikm, size_t out_len = 32);
    static std::vector<uint8_t> parseEd25519PrivateKeyFromDER(const std::vector<uint8_t>& derBytes);
    static std::vector<uint8_t> parseEd25519PublicKeyFromDER(const std::vector<uint8_t>& derBytes);
};
