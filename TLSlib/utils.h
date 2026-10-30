#pragma once

#include <vector>
#include <array>
#include <cctype>

unsigned long swapEndianLong(unsigned long value) 
{
    return ((value >> 24) & 0x000000FF) |
        ((value >> 8) & 0x0000FF00) |
        ((value << 8) & 0x00FF0000) |
        ((value << 24) & 0xFF000000);
}

unsigned short swapEndianShort(unsigned short value) {
    return (value >> 8) | (value << 8);
}

uint64_t swapEndianLongLong(uint64_t value) {
    return ((value & 0x00000000000000FFULL) << 56) |
        ((value & 0x000000000000FF00ULL) << 40) |
        ((value & 0x0000000000FF0000ULL) << 24) |
        ((value & 0x00000000FF000000ULL) << 8) |
        ((value & 0x000000FF00000000ULL) >> 8) |
        ((value & 0x0000FF0000000000ULL) >> 24) |
        ((value & 0x00FF000000000000ULL) >> 40) |
        ((value & 0xFF00000000000000ULL) >> 56);
}

uint8_t hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = std::tolower(c); // Convert to lowercase
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
}

void unhexlify(const char* in, size_t bytes, unsigned char* out) {
    for (int i = 0; i < bytes; i++) {
        unsigned char high = hexCharToInt(in[2 * i]);
        unsigned char low = hexCharToInt(in[2* i + 1]);

        out[i] = (high << 4) | low;
    }
}

typedef struct handshakes {
    unsigned char clientHello[256];
    unsigned long chLen;
    unsigned char serverHello[256];
    unsigned long shLen;
    unsigned char clientKeyExchange[256];
    unsigned long ckeLen;
} handshakes_t;

typedef struct cipherSuiteInfo {
    unsigned char MACwrite;
    unsigned char key;
    unsigned char iv;
};