#include "crow_all.h"
#include "decrypt_util.h"
#include <iostream>

int main() {
    crow::SimpleApp app;

    // Suppress Crow INFO logs
    app.loglevel(crow::LogLevel::Warning);

    CROW_ROUTE(app, "/decrypt").methods(crow::HTTPMethod::Post)(
        [](const crow::request& req) {
            auto json = crow::json::load(req.body);
            if (!json) return crow::response(400, "❌ Invalid JSON");

            std::string nonce = json["nonce"].s();
            std::string tag   = json["tag"].s();
            std::string cipher = json["cipher"].s();
            long timestamp = json["timestamp"].i();

            if (nonce.length() != 32) return crow::response(200, "❌ Invalid nonce hex");
            if (tag.length() != 32)   return crow::response(200, "❌ Invalid tag hex");
            if (cipher.length() % 2 != 0 || cipher.length() == 0 || cipher.length() > 480)
                return crow::response(200, "❌ Invalid cipher hex");

            std::string result = decrypt_payload(cipher, tag, nonce, timestamp);
            return crow::response(200, result);
        });

    std::cout << "🚀 Server started at http://0.0.0.0:5000/decrypt\n";
    app.port(5000).multithreaded().run();
}
