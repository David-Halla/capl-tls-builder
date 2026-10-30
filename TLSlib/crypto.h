#pragma once
#include <string>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define TLS_PSK_WITH_CHACHA20_POLY1305_SHA256    0xCCAB
#define TLS_PSK_WITH_AES_256_GCM_SHA384          0x00A9
#define TLS_PSK_WITH_AES_128_GCM_SHA256          0x00A8
#define TLS_PSK_WITH_AES_128_CBC_SHA256          0x00AE
#define TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 0xCCAC
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384      0x00AB
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256      0x00AA
#define TLS_PSK_WITH_NULL_SHA256                 0x00B0

typedef union keyblock {
    struct TLS_PSK_WITH_CHACHA20_POLY1305_SHA256_t {
        unsigned char clientWrite[32];
        unsigned char serverWrite[32];
        unsigned char clientIV[12];
        unsigned char serverIV[12];
    } chacha20_sha256;

    struct TLS_PSK_WITH_AES_256_GCM_SHA384_t {
        unsigned char clientWrite[32];
        unsigned char serverWrite[32];
        unsigned char clientIV[4];
        unsigned char serverIV[4];
    } aes_256_gcm_sha384;

    struct TLS_PSK_WITH_AES_128_GCM_SHA256_t
    {
        unsigned char clientWrite[16];
        unsigned char serverWrite[16];
        unsigned char clientIV[4];
        unsigned char serverIV[4];
    } aes_128_gcm_sha256;

    struct TLS_PSK_WITH_AES_128_CBC_SHA256_t
    {
        unsigned char clientMac[32];
        unsigned char serverMac[32];
        unsigned char clientWrite[16];
        unsigned char serverWrite[16];
    } aes_128_cbc_sha256;

    struct TLS_PSK_WITH_NULL_SHA256_t
    {
        unsigned char clientMac[32];
        unsigned char serverMac[32];
    } null_sha256;

} keyblock_t;

uint8_t* pkcs7(const unsigned char* payload, unsigned long len, uint16_t* outLen) {

    uint8_t toPad = 16 - (len % 16);
    uint8_t* padded = (uint8_t*)malloc(len + toPad);

    memcpy(padded, payload, len);
    memset(padded + len, toPad - 1, toPad);

    *outLen = len + toPad;

    return padded;
}

void P_hash(const char* secret, size_t secretLen, const char* seed, size_t seedLen, size_t desiredLength, unsigned short cipherSuite, void* out) {

    unsigned int hashLen;
    const EVP_MD* cipher;

    switch (cipherSuite) {
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        hashLen = 48;
        cipher = EVP_sha384();
        break;
    default:
        hashLen = 32;
        cipher = EVP_sha256();
        break;
    }

    unsigned int V;
    unsigned char* A = (unsigned char*)malloc(hashLen);
    unsigned char result[256];
    unsigned char* ASeed = (unsigned char*)malloc(hashLen + seedLen);

    HMAC(cipher, secret, secretLen, (const unsigned char*)seed, seedLen, A, &V); // A1

    memcpy(ASeed, A, hashLen);
    memcpy(ASeed + hashLen, seed, seedLen);

    for (int i = 0; i < desiredLength; i += hashLen) {

        HMAC(cipher, secret, secretLen, ASeed, seedLen + hashLen, result + i, &V);
        HMAC(cipher, secret, secretLen, A, hashLen, A, &V);
        memcpy(ASeed, A, hashLen);
    }

    memcpy(out, result, desiredLength);

    free(A);
    free(ASeed);
}

void PRF(char* secret, size_t secretLen, std::string label, char* seed, size_t seedLen, size_t desiredLen, unsigned short cipherSuite, void* out) {

    char* extendedSeed = (char*)malloc(label.length() + seedLen);
    memcpy(extendedSeed, label.data(), label.length());
    memcpy(extendedSeed + label.length(), seed, seedLen);

    P_hash(secret, secretLen, extendedSeed, label.length() + seedLen, desiredLen, cipherSuite, out);
    free(extendedSeed);
}

unsigned char hash(unsigned char* buffer, size_t len, unsigned short cipherSuite, unsigned char* out) {
    switch (cipherSuite) {
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:

        SHA384(buffer, len, out);
        return 48;
        break;
    default:
        SHA256(buffer, len, out);
        return 32;
        break;
    }
}

unsigned long tls_encrypt(uint16_t cipherSuite, const unsigned char* data, unsigned long dataLen,
    const char* explicitNonce, keyblock_t keyblock, unsigned char* out, uint64_t seq, unsigned int encryptThenMac)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    int len = 0, ciphertext_len = 0;
    unsigned char tag[16];
    unsigned char nonce[12];

    unsigned char* key = nullptr;
    unsigned char keyLen;
    unsigned char* macInput;
    unsigned long outLen;

    // Nonce handling (IV + explicitNonce) — standard for AES-GCM & ChaCha20-Poly1305
    // individual for each cipher suite

    // Build AAD
    unsigned char aad[13];
    uint64_t seqRev = swapEndianLongLong(seq);
    uint16_t dataLenRev = swapEndianShort(dataLen);
    memcpy(aad, &seqRev, 8);
    aad[8] = 0x16;  // TLS record type (handshake/application data) — adjust if needed
    aad[9] = 0x03;  // TLS version major
    aad[10] = 0x03; // TLS version minor (TLS 1.2)
    memcpy(aad + 11, &dataLenRev, 2);


    const EVP_CIPHER* cipher = nullptr;

    switch (cipherSuite) {
    case TLS_PSK_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        
        cipher = EVP_aes_128_gcm();
        key = keyblock.aes_128_gcm_sha256.clientWrite;
        keyLen = 16;
        memcpy(nonce, keyblock.aes_128_gcm_sha256.clientIV, 4);
        memcpy(nonce + 4, explicitNonce, 8);

        break;
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
       
        cipher = EVP_aes_256_gcm();
        key = keyblock.aes_256_gcm_sha384.clientWrite;
        keyLen = 32;
        memcpy(nonce, keyblock.aes_256_gcm_sha384.clientIV, 4);
        memcpy(nonce + 4, explicitNonce, 8);

        break;
    case TLS_PSK_WITH_AES_128_CBC_SHA256:
        cipher = EVP_aes_128_cbc(); // needs manual HMAC-SHA256
        key = keyblock.aes_128_cbc_sha256.clientWrite;
        keyLen = 16;

        break;
    case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        cipher = EVP_chacha20_poly1305();
        key = keyblock.chacha20_sha256.clientWrite;
        keyLen = 32;

        memcpy(nonce, keyblock.chacha20_sha256.clientIV, 4);
        for (size_t i = 0; i < 8; i++) {
            nonce[4 + i] = *(uint8_t*)(((uint64_t)&seqRev) + i) ^ keyblock.chacha20_sha256.clientIV[4 + i];
        }

        break;
    case TLS_PSK_WITH_NULL_SHA256:
        EVP_CIPHER_CTX_free(ctx);

        uint32_t macLen;
        /*
        HMAC_CTX* hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx, keyblock.null_sha256.clientMac, 32, EVP_sha256(), nullptr);
        HMAC_Update(hctx, data, dataLen);
        HMAC_Final(hctx, out + dataLen, &len);
        HMAC_CTX_free(hctx);
        */
        macInput = (unsigned char*)malloc(dataLen + 13);
        memcpy(macInput, aad, 13);
        memcpy(macInput + 13, data, dataLen);

        memcpy(out, data, dataLen);
        HMAC(EVP_sha256(), keyblock.aes_128_cbc_sha256.clientMac, 32, macInput, dataLen + 13, out + dataLen, &macLen);
        free(macInput);

        return 32 + dataLen; // no encryption, only MAC in real TLS
        break;
    default:
        EVP_CIPHER_CTX_free(ctx);
        return 0; // unsupported suite
    }

    // Initialize encryption
    EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);

    if (cipher == EVP_chacha20_poly1305()) {

        //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce);

        // AAD
        EVP_EncryptUpdate(ctx, nullptr, &len, aad, sizeof(aad));

        // Ciphertext
        EVP_EncryptUpdate(ctx, out, &len, data, dataLen);
        ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx, out + len, &len);
        ciphertext_len += len;


        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        memcpy(out + dataLen, tag, 16);

        outLen = 16 + dataLen;

    } else if (cipher == EVP_aes_128_gcm() || cipher == EVP_aes_256_gcm()) {
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce);

        // AAD
        EVP_EncryptUpdate(ctx, nullptr, &len, aad, sizeof(aad));

        // Ciphertext
        EVP_EncryptUpdate(ctx, out + 8, &len, data, dataLen);
        ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx, out + 8 + len, &len);
        ciphertext_len += len;

        

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

        // Format TLS record: explicit nonce (8B) || ciphertext || tag
        //unhexlify("0000000000000000", 8, out);
        memcpy(out, explicitNonce, 8);
        memcpy(out + 8 + dataLen, tag, 16);
        outLen = 16 + 8 + dataLen;
    }
    else if (cipher == EVP_aes_128_cbc()) {

        if (encryptThenMac) {

            uint16_t paddedLen;
            unsigned char* paddedData = pkcs7(data, dataLen, &paddedLen);

            unsigned char iv[16] = { 0 };
            iv[0] = 0xff;
            iv[15] = 0xff;

            unsigned char updateOut[80] = { 0 };
            unsigned char finalOut[80] = { 0 };

            
            EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv);
            //EVP_EncryptUpdate(ctx, updateOut, &len, paddedData, paddedLen);
            EVP_EncryptUpdate(ctx, out + 16, &len, paddedData, paddedLen);
            ciphertext_len = len;

            //EVP_EncryptFinal_ex(ctx, out + 16 + len, &len);
            //EVP_EncryptFinal_ex(ctx, finalOut, &len);
            //ciphertext_len += len;

            memcpy(out, iv, 16);

            free(paddedData);


            uint16_t paddedLenInput = swapEndianShort(paddedLen + 16);
            memcpy(aad + 11, &paddedLenInput, 2);

            macInput = (unsigned char*)malloc(ciphertext_len + 16 + 13);
            memcpy(macInput, aad, 13);
            memcpy(macInput + 13, iv, 16);
            memcpy(macInput + 16 + 13, out + 16, ciphertext_len);

            unsigned char MAC[32];
            uint32_t macLen;

            HMAC(EVP_sha256(), keyblock.aes_128_cbc_sha256.clientMac, 32, macInput, ciphertext_len + 16 + 13, MAC, &macLen);

            memcpy(out + 16 + ciphertext_len, MAC, 32);

            free(macInput);
            outLen = paddedLen + 16 + 32;
        }
        else {
            // MAC-THEN-ENCRYPT


            
            // Compute MAC over AAD || Plaintext

            unsigned char iv[16] = { 0 };
            iv[0] = 0xff;
            iv[15] = 0xff;

            macInput = (unsigned char*)malloc(dataLen + 13 + 16);
            memcpy(macInput, aad, 13);
            memcpy(macInput + 13, data, dataLen);

            unsigned char MAC[32];
            unsigned int macLen;

            HMAC(EVP_sha256(), keyblock.aes_128_cbc_sha256.clientMac, 32, macInput, dataLen + 13, MAC, &macLen);

            free(macInput);
            
            // Append MAC to plaintext

            uint16_t plainMacLen = dataLen + 32;
            unsigned char* plainMac = (unsigned char*)malloc(plainMacLen);

            memcpy(plainMac, data, dataLen);
            memcpy(plainMac + dataLen, MAC, 32);

            //Apply PKCS#7 padding

            uint16_t paddedLen;
            unsigned char* paddedData = pkcs7(plainMac, plainMacLen, &paddedLen);
            free(plainMac);

            //Encrypt padded (Plaintext || MAC)

            memcpy(out, iv, 16);

            EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

            EVP_EncryptUpdate(ctx, out + 16, &len, paddedData, paddedLen);
            ciphertext_len = len;

            uint8_t finalized[16] = {0};

            EVP_EncryptFinal_ex(ctx, finalized, &len);
            //EVP_EncryptFinal_ex(ctx, out + 16 + len, &len);
            
            //ciphertext_len += len;

            free(paddedData);

            outLen = 16 + ciphertext_len;
        }

    }

    EVP_CIPHER_CTX_free(ctx);
    return outLen;
}

unsigned short getHashMode(unsigned short cipherSuite) {
    
    switch (cipherSuite) {
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
        return 384;
        break;
    default:
        return 256;
        break;
    }

}