#include "civetweb.h"
#include <iostream>
#include <string>
#include <cstring>
#include <ctime>
#include <json/json.h>  // We'll use jsoncpp

extern "C" {
    #include "crypto_aead.h"
    #include "ascon_hash.h"
}

#define PORT "5000"
#define AD_STR "device=ESP32"

// Helper to convert hex string to binary
bool hex2bin(const std::string& hex, uint8_t* bin, size_t len) {
    if (hex.size() != len * 2) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte;
        if (sscanf(hex.substr(i * 2, 2).c_str(), "%2x", &byte) != 1) return false;
        bin[i] = (uint8_t)byte;
    }
    return true;
}

// Derive 16-byte key from slot string using ASCON-HASH
void derive_key_from_slot(const std::string& slot, uint8_t* key) {
    uint8_t hash[32];
    ascon_hash((const uint8_t*)slot.c_str(), slot.length(), hash);
    memcpy(key, hash, 16);
}

// Convert timestamp to slot string
std::string get_slot_string_from_timestamp(time_t ts) {
    std::tm* t = localtime(&ts);
    int slot_hour = (t->tm_hour / 6) * 6;
    char buf[13];
    sprintf(buf, "%04d%02d%02d%02d", 1900 + t->tm_year, 1 + t->tm_mon, t->tm_mday, slot_hour);
    return std::string(buf);
}

// Print decrypted output
void print_result(const char* plaintext, time_t ts) {
    std::tm* t = localtime(&ts);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
    std::cout << "---------Decrypted cipher text---------\n";
    std::cout << "time - " << timebuf << "\n";
    std::cout << plaintext << std::endl;
}

class DecryptHandler : public CivetHandler {
public:
    bool handlePost(CivetServer* server, struct mg_connection* conn) override {
        char buffer[1024];
        int ret = mg_read(conn, buffer, sizeof(buffer));
        std::string body(buffer, ret);

        Json::Value root;
        Json::Reader reader;
        if (!reader.parse(body, root)) {
            mg_printf(conn, "HTTP/1.1 400 Bad Request\r\n\r\nInvalid JSON\n");
            return true;
        }

        std::string nonce_hex = root.get("nonce", "").asString();
        std::string tag_hex = root.get("tag", "").asString();
        std::string cipher_hex = root.get("cipher", "").asString();
        time_t timestamp = root.get("timestamp", 0).asInt64();

        uint8_t nonce[16], tag[16], cipher[240], key[16];
        if (!hex2bin(nonce_hex, nonce, 16) || !hex2bin(tag_hex, tag, 16)) {
            mg_printf(conn, "HTTP/1.1 400 Bad Request\r\n\r\nInvalid nonce/tag format\n");
            return true;
        }

        size_t cipher_len = cipher_hex.length() / 2;
        if (!hex2bin(cipher_hex, cipher, cipher_len)) {
            mg_printf(conn, "HTTP/1.1 400 Bad Request\r\n\r\nInvalid cipher format\n");
            return true;
        }

        std::string slot = get_slot_string_from_timestamp(timestamp);
        derive_key_from_slot(slot, key);

        uint8_t full_ct[256];
        memcpy(full_ct, cipher, cipher_len);
        memcpy(full_ct + cipher_len, tag, 16);

        uint8_t plaintext[256] = {0};
        unsigned long long mlen = 0;

        int result = crypto_aead_decrypt(
            plaintext, &mlen, NULL,
            full_ct, cipher_len + 16,
            (const uint8_t*)AD_STR, strlen(AD_STR),
            nonce, key
        );

        if (result == 0) {
            plaintext[mlen] = '\0';
            print_result((char*)plaintext, timestamp);
            mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK\n");
        } else {
            mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDECRYPTION FAILED\n");
        }
        return true;
    }
};

int main() {
    const char* options[] = { "listening_ports", PORT, 0 };
    CivetServer server(options);

    DecryptHandler handler;
    server.addHandler("/decrypt", handler);

    std::cout << "🔒 ASCON Decrypt Server running at http://localhost:" << PORT << "/decrypt\n";
    while (true) Sleep(1000);
    return 0;
}
