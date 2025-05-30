#include "../include/encryption.h"

std::vector<uint8_t> Encryption::parseEd25519PrivateKeyFromDER(const std::vector<uint8_t>& derBytes) {
    const unsigned char* p = derBytes.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, derBytes.size());
    if (!pkey)
        throw std::runtime_error("Failed to parse private key DER");

    size_t keylen = 0;
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &keylen) != 1) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get raw private key length");
    }

    std::vector<uint8_t> privKey(keylen);
    if (EVP_PKEY_get_raw_private_key(pkey, privKey.data(), &keylen) != 1) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get raw private key");
    }
    EVP_PKEY_free(pkey);
    return privKey;
}

std::vector<uint8_t> Encryption::parseEd25519PublicKeyFromDER(const std::vector<uint8_t>& derBytes) {
    const unsigned char* p = derBytes.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, derBytes.size());
    if (!pkey)
        throw std::runtime_error("Failed to parse public key DER");

    size_t keylen = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &keylen) != 1) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get raw public key length");
    }

    std::vector<uint8_t> pubKey(keylen);
    if (EVP_PKEY_get_raw_public_key(pkey, pubKey.data(), &keylen) != 1) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get raw public key");
    }
    EVP_PKEY_free(pkey);
    return pubKey;
}

std::vector<uint8_t> Encryption::ed25519PrivToX25519(const std::vector<uint8_t>& edPriv) {
    if (edPriv.size() != 32)
        throw std::runtime_error("Invalid Ed25519 private key size");

    std::vector<uint8_t> x25519Priv(32);
    if (crypto_sign_ed25519_sk_to_curve25519(x25519Priv.data(), edPriv.data()) != 0)
        throw std::runtime_error("Conversion failed");

    return x25519Priv;
}

std::vector<uint8_t> Encryption::ed25519PubToX25519(const std::vector<uint8_t>& edPub) {
    if (edPub.size() != 32)
        throw std::runtime_error("Invalid Ed25519 public key size");

    std::vector<uint8_t> x25519Pub(32);
    if (crypto_sign_ed25519_pk_to_curve25519(x25519Pub.data(), edPub.data()) != 0)
        throw std::runtime_error("Conversion failed");

    return x25519Pub;
}

// Performs X25519 ECDH to get shared secret
std::vector<uint8_t> Encryption::x25519ECDH(const std::vector<uint8_t>& x25519Priv,
                                            const std::vector<uint8_t>& x25519Pub) {
    EVP_PKEY* priv_key = nullptr;
    EVP_PKEY* peer_key = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    std::vector<uint8_t> secret(32);

    {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(NID_X25519, nullptr);
        if (!pctx)
            throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("EVP_PKEY_keygen_init failed");
        }

        EVP_PKEY_CTX_free(pctx);

        priv_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, x25519Priv.data(), x25519Priv.size());
        if (!priv_key)
            throw std::runtime_error("Failed to create EVP_PKEY private key");
    }

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, x25519Pub.data(), x25519Pub.size());
    if (!peer_key) {
        EVP_PKEY_free(priv_key);
        throw std::runtime_error("Failed to create EVP_PKEY public key");
    }

    ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_key);
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_key);
        throw std::runtime_error("EVP_PKEY_derive_init or set_peer failed");
    }

    size_t secret_len = secret.size();
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_key);
        throw std::runtime_error("EVP_PKEY_derive failed");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_key);

    secret.resize(secret_len);
    return secret;
}

// HKDF-SHA256 to derive key from shared secret
std::vector<uint8_t> Encryption::hkdfSha256(const std::vector<uint8_t>& ikm, size_t out_len) {
    std::vector<uint8_t> okm(out_len);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx)
        throw std::runtime_error("Failed to create HKDF context");

    if (EVP_PKEY_derive_init(pctx) <= 0)
        throw std::runtime_error("Failed to init HKDF derive");

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        throw std::runtime_error("Failed to set HKDF MD");

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0) <= 0)
        throw std::runtime_error("Failed to set HKDF salt");

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0)
        throw std::runtime_error("Failed to set HKDF key");

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, nullptr, 0) <= 0)
        throw std::runtime_error("Failed to set HKDF info");

    size_t len = okm.size();
    if (EVP_PKEY_derive(pctx, okm.data(), &len) <= 0)
        throw std::runtime_error("Failed to derive HKDF key");

    EVP_PKEY_CTX_free(pctx);
    return okm;
}

std::vector<uint8_t> Encryption::deriveKey(const std::string& privateKeyBase64, const std::string& publicKeyBase64) {
    auto privateKeyDer = Util::base64Decode(privateKeyBase64);
    auto publicKeyDer = Util::base64Decode(publicKeyBase64);

    auto rawPriv = parseEd25519PrivateKeyFromDER(privateKeyDer);
    auto rawPub = parseEd25519PublicKeyFromDER(publicKeyDer);

    auto xPriv = ed25519PrivToX25519(rawPriv);
    auto xPub = ed25519PubToX25519(rawPub);

    auto sharedSecret = x25519ECDH(xPriv, xPub);
    auto derivedKey = hkdfSha256(sharedSecret, 32);

    return derivedKey;
}

std::vector<uint8_t> Encryption::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    if (key.size() != 32)
        throw std::runtime_error("ChaCha20-Poly1305 requires 256-bit key");

    const int nonce_len = 12;
    const int tag_len = 16;
    std::vector<uint8_t> nonce(nonce_len);
    if (RAND_bytes(nonce.data(), nonce_len) != 1)
        throw std::runtime_error("Failed to generate nonce");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(plaintext.size() + tag_len);

    int len;
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    int out_len;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plaintext.data(), plaintext.size());

    int total_len = out_len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &len);
    total_len += len;

    std::vector<uint8_t> tag(tag_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag.data());

    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> result;
    result.reserve(nonce_len + total_len + tag_len);
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + total_len);
    result.insert(result.end(), tag.begin(), tag.end());

    return result;
}

std::vector<uint8_t> Encryption::decrypt(const std::vector<uint8_t>& encrypted, const std::vector<uint8_t>& key) {
    if (key.size() != 32)
        throw std::runtime_error("ChaCha20-Poly1305 requires 256-bit key");

    const int nonce_len = 12;
    const int tag_len = 16;

    if (encrypted.size() < nonce_len + tag_len)
        throw std::runtime_error("Encrypted data too short");

    const uint8_t* nonce = encrypted.data();
    const uint8_t* ciphertext = encrypted.data() + nonce_len;
    size_t ciphertext_len = encrypted.size() - nonce_len - tag_len;
    const uint8_t* tag = encrypted.data() + encrypted.size() - tag_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plaintext(ciphertext_len);

    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce);

    int len;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, (void*)tag);

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0)
        throw std::runtime_error("Decryption failed: tag mismatch or corrupted data");

    return plaintext;
}
