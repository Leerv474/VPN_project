#include "../include/authenticator.h"

Authenticator::Authenticator(const std::string& privateKeyPem) { loadPrivateKey(privateKeyPem); }

Authenticator::~Authenticator() {
    if (privateKey)
        EVP_PKEY_free(privateKey);
}

void Authenticator::loadPrivateKey(const std::string& privateKeyBase64) {
    auto keyBytes = Util::base64Decode(privateKeyBase64);
    const unsigned char* ptr = keyBytes.data();

    privateKey = d2i_AutoPrivateKey(nullptr, &ptr, keyBytes.size());
    if (!privateKey)
        throw std::runtime_error("Failed to parse DER Ed25519 private key");
}

EVP_PKEY* Authenticator::loadPublicKey(const std::string& publicKeyBase64) {
    auto keyBytes = Util::base64Decode(publicKeyBase64);
    const unsigned char* ptr = keyBytes.data();

    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &ptr, keyBytes.size());
    if (!pkey)
        throw std::runtime_error("Failed to parse DER Ed25519 public key");

    return pkey;
}

std::vector<uint8_t> Authenticator::generateChallenge(size_t size) {
    std::vector<uint8_t> challenge(size);
    std::random_device rd;
    std::generate(challenge.begin(), challenge.end(), std::ref(rd));
    return challenge;
}

std::vector<uint8_t> Authenticator::signChallenge(const std::vector<uint8_t>& challenge) {
    size_t sigLen = 0;
    std::vector<uint8_t> signature(EVP_PKEY_size(privateKey));

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create MD context");

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, privateKey) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSignInit failed");
    }

    sigLen = signature.size();
    if (EVP_DigestSign(ctx, signature.data(), &sigLen, challenge.data(), challenge.size()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestSign failed");
    }

    signature.resize(sigLen);
    EVP_MD_CTX_free(ctx);
    return signature;
}

bool Authenticator::verifyChallenge(const std::string& publicKeyStr, const std::vector<uint8_t>& challenge,
                                    const std::vector<uint8_t>& signature) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> publicKey(loadPublicKey(publicKeyStr), EVP_PKEY_free);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create MD context");

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, publicKey.get()) <= 0) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestVerifyInit failed");
    }

    int ret = EVP_DigestVerify(ctx, signature.data(), signature.size(), challenge.data(), challenge.size());
    EVP_MD_CTX_free(ctx);

    return ret == 1;
}
