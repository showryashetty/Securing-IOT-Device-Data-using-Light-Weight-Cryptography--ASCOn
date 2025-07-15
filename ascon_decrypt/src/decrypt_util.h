#pragma once
#include <string>

std::string decrypt_payload(const std::string& cipher_hex,
                            const std::string& tag_hex,
                            const std::string& nonce_hex,
                            long timestamp);
