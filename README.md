# Securing-IOT-Device-Data-using-Light-Weight-Cryptography--ASCOn
Designed and implemented secure IoT data transmission using lightweight cryptography (ASCON), optimized for low memory, latency, and power usage. Ensured data 
Step	Role	Device/Software


The data was encrypted on an ESP32 device, not inside VS Code or any PC server.

The encryption likely used the same ASCON AEAD method and timestamp-based key logic.

Your current code, built in VS Code and run on a Crow C++ HTTP server, is only doing the decryption part.


1	Encryption	On ESP32 (e.g., C code using ASCON AEAD)
2	Send encrypted data to server	ESP32 sends data to your HTTP API
3	Decryption	Your Crow C++ web server (probably run via VS Code or g++) decrypts the payload
