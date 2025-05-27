#include "../include/authenticator.h"

Authenticator::Authenticator(const std::string& privateKeyPath, const std::string& publicKeyPath) {
    if (!privateKeyPath.empty()) loadPrivateKey(privateKeyPath);
    if (!publicKeyPath.empty()) loadPublicKey(publicKeyPath);
}

void Authenticator::loadPrivateKey(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) throw std::runtime_error("Unable to open private key file");
    privateKey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!privateKey) throw std::runtime_error("Failed to load private key");
}

void Authenticator::loadPublicKey(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) throw std::runtime_error("Unable to open public key file");
    publicKey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!publicKey) throw std::runtime_error("Failed to load public key");
}

std::vector<uint8_t> Authenticator::generateChallenge(size_t size) {
    std::vector<uint8_t> challenge(size);
    if (!RAND_bytes(challenge.data(), size)) {
        throw std::runtime_error("Failed to generate random challenge");
    }
    return challenge;
}

std::vector<uint8_t> Authenticator::signChallenge(const std::vector<uint8_t>& challenge) {
    if (!privateKey) throw std::runtime_error("Private key not loaded");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, challenge.data(), challenge.size());

    std::vector<uint8_t> signature(EVP_PKEY_size(privateKey));
    unsigned int sigLen;
    EVP_SignFinal(ctx, signature.data(), &sigLen, privateKey);
    signature.resize(sigLen);

    EVP_MD_CTX_free(ctx);
    return signature;
}

bool Authenticator::verifyChallenge(const std::vector<uint8_t>& challenge, const std::vector<uint8_t>& signature) {
    if (!publicKey) throw std::runtime_error("Public key not loaded");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, challenge.data(), challenge.size());

    int result = EVP_VerifyFinal(ctx, signature.data(), signature.size(), publicKey);
    EVP_MD_CTX_free(ctx);
    return result == 1;
}

