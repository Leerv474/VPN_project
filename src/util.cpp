#include "../include/util.h"

std::pair<std::string, int> Util::splitBy(const std::string& string, const char& separator) {
    size_t pos = string.find(separator);
    // std::cout << "Trying to separate " << string << " " << separator << "\n\n";
    if (pos == std::string::npos) {
        throw std::invalid_argument("Separator not found");
    }

    std::string ip = string.substr(0, pos);
    int remainder = std::stoi(string.substr(pos + 1));

    return {ip, remainder};
}

std::string Util::base64Encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    BIO_push(b64, bio);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);

    BIO_free_all(b64);
    return encoded;
}

std::pair<std::string, std::string> Util::generateKeyPairBase64() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx)
        throw std::runtime_error("Failed to create context");

    if (EVP_PKEY_keygen_init(pctx) <= 0)
        throw std::runtime_error("Init failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        throw std::runtime_error("Keygen failed");

    // Private key DER
    uint8_t* privBuf = nullptr;
    int privLen = i2d_PrivateKey(pkey, &privBuf);
    if (privLen <= 0)
        throw std::runtime_error("Private key export failed");
    std::vector<uint8_t> privVec(privBuf, privBuf + privLen);
    OPENSSL_free(privBuf);

    // Public key DER
    uint8_t* pubBuf = nullptr;
    int pubLen = i2d_PUBKEY(pkey, &pubBuf);
    if (pubLen <= 0)
        throw std::runtime_error("Public key export failed");
    std::vector<uint8_t> pubVec(pubBuf, pubBuf + pubLen);
    OPENSSL_free(pubBuf);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    return {base64Encode(privVec), base64Encode(pubVec)};
}

void Util::printHex(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (uint8_t byte : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    std::cout << std::dec << "\n";
}


std::vector<uint8_t> Util::base64Decode(const std::string& base64) {
    BIO* bio = BIO_new_mem_buf(base64.c_str(), -1);
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Handle single-line Base64

    std::vector<uint8_t> buffer;
    const int chunkSize = 512;
    std::vector<uint8_t> temp(chunkSize);

    int len;
    while ((len = BIO_read(bio, temp.data(), chunkSize)) > 0) {
        buffer.insert(buffer.end(), temp.begin(), temp.begin() + len);
    }

    BIO_free_all(bio);

    if (buffer.empty()) {
        throw std::runtime_error("Base64 decode failed or produced no data");
    }
    return buffer;
}

