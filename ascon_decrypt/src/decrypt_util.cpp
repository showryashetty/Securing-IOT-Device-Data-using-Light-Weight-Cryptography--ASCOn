#include "decrypt_util.h"
#include "ascon_hash.h"
#include "crypto_aead.h"

#include <string>
#include <vector>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdio>
#include <cctype>
#include <iostream>

#define AD_STR "device=ESP32"

void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; ++i)
        printf("%02X", data[i]);
    std::cout << std::endl;
}

bool hex2bin(const std::string& hex, uint8_t* bin, size_t expected_len) {
    if (hex.length() != expected_len * 2) return false;
    for (size_t i = 0; i < expected_len; ++i) {
        char hex_pair[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        if (!std::isxdigit(hex_pair[0]) || !std::isxdigit(hex_pair[1])) return false;
        int byte;
        if (sscanf(hex_pair, "%2x", &byte) != 1) return false;
        bin[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

std::string decrypt_payload(const std::string& cipher_hex,
                            const std::string& tag_hex,
                            const std::string& nonce_hex,
                            long timestamp) {
    uint8_t nonce[16], tag[16], key[16], hash[32];
    std::vector<uint8_t> cipher;

    // Convert hex inputs
    if (!hex2bin(nonce_hex, nonce, 16) ||
        !hex2bin(tag_hex, tag, 16) ||
        cipher_hex.length() % 2 != 0 ||
        cipher_hex.length() / 2 > 240) {
        return "";  // Silently ignore invalid input
    }

    size_t cipher_len = cipher_hex.length() / 2;
    cipher.resize(cipher_len);
    if (!hex2bin(cipher_hex, cipher.data(), cipher_len)) {
        return "";
    }

    // Match ESP32 timezone (IST)
    setenv("TZ", "Asia/Kolkata", 1);
    tzset();

    std::tm* tm_info = localtime(&timestamp);
    if (!tm_info) return "";

    int slot_hour = (tm_info->tm_hour / 6) * 6;
    char slot_str[20];
    snprintf(slot_str, sizeof(slot_str), "%04d%02d%02d%02d",
             1900 + tm_info->tm_year,
             1 + tm_info->tm_mon,
             tm_info->tm_mday,
             slot_hour);

    ascon_hash(reinterpret_cast<const uint8_t*>(slot_str), strlen(slot_str), hash);
    memcpy(key, hash, 16);

    cipher.insert(cipher.end(), tag, tag + 16);

    uint8_t plaintext[256] = {0};
    unsigned long long mlen = 0;

    int result = crypto_aead_decrypt(
        plaintext, &mlen,
        nullptr,
        cipher.data(), cipher.size(),
        reinterpret_cast<const uint8_t*>(AD_STR), strlen(AD_STR),
        nonce,
        key
    );

    if (result == 0) {
        plaintext[mlen] = '\0';

        // Format readable IST time
        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

        // Format output
        std::cout << "--------------Decrypted cipher text-----------------" << std::endl;
        std::cout << "Time       - " << time_buf << std::endl;
        std::cout << "Decrypted  - " << std::string(reinterpret_cast<char*>(plaintext)) << std::endl;
        std::cout << "-------------------------------------------------------" << std::endl;

        return std::string(reinterpret_cast<char*>(plaintext));
    } else {
        return "";  // Silent failure
    }
} // ✅ <-- This was missing before
