#include <Arduino.h>
#include <WiFi.h>
#include <DHT.h>
#include "ascon128_wrapper.h"
#include <time.h>
#include <FS.h>
#include <SPIFFS.h>
#include <vector>
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_timer.h"
#include <HTTPClient.h>

// ========== CONFIGURATION ==========
#define WIFI_SSID               "ASCON"
#define WIFI_PASSWORD           "9035779171"

#define DHTPIN                  15
#define DHTTYPE                 DHT11
#define TRIG_PIN                13
#define ECHO_PIN                12
#define AD_STR "device=ESP32"
uint64_t wifiDisconnectedSince = 0;

// Server configuration
const char* serverUrl = "http://192.168.20.4:5000/decrypt";
bool reconnectedBeforeTimeout = false;

// Minimum plausible year for time sync
#define MIN_PLAUSIBLE_YEAR (2020 - 1900)

// Maximum size for the offline data file in KB.
#define MAX_OFFLINE_FILE_SIZE_KB 10
#define MAX_OFFLINE_FILE_SIZE_BYTES (MAX_OFFLINE_FILE_SIZE_KB * 1024)

// DHT Sensor retry configuration
#define DHT_MAX_RETRIES           3
#define DHT_RETRY_DELAY_MS        100

// Deep Sleep Configuration
#define DEEP_SLEEP_DISCONNECT_THRESHOLD_SEC 30UL
#define DEEP_SLEEP_DURATION_SEC             60

// NTP sync interval
#define NTP_SYNC_INTERVAL_MS                3600000UL
#define NTP_SYNC_TIMEOUT_MS                 10000UL

// HTTP request timeout
#define HTTP_TIMEOUT_MS 5000

// ========== GLOBALS ==========
DHT dht(DHTPIN, DHTTYPE);

char plaintext[64];
uint8_t ciphertext[80];
unsigned long long clen = 0;

const char* ntpServer = "pool.ntp.org";
const long gmtOffset_sec = 19800;
const int daylightOffset_sec = 0;

unsigned int totalSent = 0;

unsigned long lastSensorReadTime = 0;
const unsigned long SENSOR_READ_INTERVAL_MS = 5000;

// Variables to store last known good sensor values
float lastValidTemp = NAN;
float lastValidHumi = NAN;

// Tracks last time we were fully connected OR successfully sent data
uint64_t lastSuccessfullyConnectedOrSent = 0;
uint64_t lastNtpSyncTime = 0;

// State for non-blocking WiFi retries
unsigned long lastWifiAttempt = 0;
const unsigned long WIFI_RETRY_INTERVAL_MS = 5000;

// Global for persistent time information
struct tm lastKnownGoodTimeinfo;
bool hasSyncedTime = false;

// ========== HELPER FUNCTION DEFINITIONS ==========

void tryConnectWiFi() {
  if (WiFi.status() != WL_CONNECTED) {
    if (millis() - lastWifiAttempt > WIFI_RETRY_INTERVAL_MS) {
      Serial.println("\U0001F4F1 Retrying WiFi connection...");
      WiFi.disconnect(false); // Non-blocking disconnect
      WiFi.begin(WIFI_SSID, WIFI_PASSWORD); // Non-blocking
      lastWifiAttempt = millis();
    }
  }
}

void syncTime() {
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
  Serial.print("\n\u23F3 Waiting for NTP time...");
  time_t now;
  struct tm temp_timeinfo;

  bool timeSynced = false;
  unsigned long syncStartTime = millis();

  while (millis() - syncStartTime < NTP_SYNC_TIMEOUT_MS) {
    now = time(nullptr);
    timeSynced = getLocalTime(&temp_timeinfo, now);
    if (timeSynced && temp_timeinfo.tm_year >= MIN_PLAUSIBLE_YEAR) {
        break;
    }
    delay(500);
    Serial.print(".");
  }

  if (!timeSynced || temp_timeinfo.tm_year < MIN_PLAUSIBLE_YEAR) {
    Serial.println("\n❌ Time sync failed after multiple attempts!");
  } else {
    Serial.println("\n\U0001F552 Time synced!");
    lastKnownGoodTimeinfo = temp_timeinfo;
    hasSyncedTime = true;
  }
  lastNtpSyncTime = esp_timer_get_time();
}

String getTimeSlotString(struct tm& timeinfo) {
  char buf[13];
  int hourSlot = (timeinfo.tm_hour / 6) * 6; // 0, 6, 12, 18 (4-hour slots)
  sprintf(buf, "%04d%02d%02d%02d", 1900 + timeinfo.tm_year,
          1 + timeinfo.tm_mon, timeinfo.tm_mday, hourSlot);
  return String(buf);
}

void deriveKeyFromTimeSlot(const String& slot, uint8_t* key_out) {
    uint8_t hash_output[ASCON_HASH_SIZE];
    
    // Use ASCON-HASH to derive key
    ascon_hash((const uint8_t*)slot.c_str(), slot.length(), hash_output);
    
    // Use first 16 bytes of hash output as key
    memcpy(key_out, hash_output, 16);
    
    // Securely wipe temporary buffer
    memset(hash_output, 0, sizeof(hash_output));
}

void printHexKey(const char* label, const uint8_t* data, size_t len) {
  Serial.print(label);
  for (size_t i = 0; i < len; ++i) {
    char buf[3];
    sprintf(buf, "%02X", data[i]);
    Serial.print(buf);
  }
  Serial.println();
}

float getUltrasonicCM() {
  digitalWrite(TRIG_PIN, LOW); delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH); delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);
  long duration = pulseIn(ECHO_PIN, HIGH, 30000);
  if (duration == 0 || duration >= 30000) {
      return -1.0;
  }
  return duration * 0.0343 / 2.0;
}

void generateUniqueNonce(uint8_t* nonce) {
    uint32_t r_data[4];
    r_data[0] = esp_random();
    r_data[1] = esp_random();
    r_data[2] = esp_random();
    r_data[3] = esp_random();

    time_t t_sec = time(nullptr);
    uint32_t t_micros = micros();

    r_data[0] ^= (uint32_t)t_sec;
    r_data[1] ^= t_micros;

    memcpy(nonce, r_data, 16);
}

bool offlinePayloadsExist() {
  File file = SPIFFS.open("/offline_data.txt", FILE_READ);
  bool exists = file && file.size() > 0;
  if (file) file.close();
  return exists;
}

void manageOfflineStorage(size_t new_payload_size) {
  if (!SPIFFS.exists("/offline_data.txt")) {
    return;
  }

  File file = SPIFFS.open("/offline_data.txt", FILE_READ);
  if (!file) {
    Serial.println("❌ manageOfflineStorage: Failed to open offline data file for reading!");
    return;
  }

  size_t current_file_size = file.size();
  
  if (current_file_size + new_payload_size < MAX_OFFLINE_FILE_SIZE_BYTES) {
    file.close();
    return;
  }

  Serial.printf("⚠️ Offline storage exceeding limit (%dKB). Truncating oldest data.\n", MAX_OFFLINE_FILE_SIZE_KB);
  std::vector<String> all_lines;
  while (file.available()) {
    String line = file.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) {
      all_lines.push_back(line);
    }
  }
  file.close();

  std::vector<String> lines_to_keep;
  size_t bytes_kept = 0;

  for (int i = all_lines.size() - 1; i >= 0; i--) {
    size_t line_len_with_newline = all_lines[i].length() + 1;
    if (bytes_kept + line_len_with_newline + new_payload_size < MAX_OFFLINE_FILE_SIZE_BYTES) {
      lines_to_keep.insert(lines_to_keep.begin(), all_lines[i]);
      bytes_kept += line_len_with_newline;
    } else {
      break;
    }
  }
  
  File outFile = SPIFFS.open("/offline_data.txt", FILE_WRITE);
  if (!outFile) {
    Serial.println("❌ manageOfflineStorage: Failed to open offline data file for rewriting!");
    return;
  }

  for (const auto& line : lines_to_keep) {
    outFile.println(line);
  }
  outFile.close();
  Serial.printf("✅ Offline storage truncated. Kept %d lines (approx %d bytes).\n", lines_to_keep.size(), bytes_kept);
}

void savePayloadOffline(const String& payload) {
  manageOfflineStorage(payload.length() + 1);
  File file = SPIFFS.open("/offline_data.txt", FILE_APPEND);
  if (!file) {
    Serial.println("❌ Failed to open file for writing offline data!");
    return;
  }
  file.println(payload);
  file.close();
  Serial.println("\U0001F4BE Saved payload offline...");
}

bool sendToServer(const String& payload) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("❌ Not connected to WiFi, cannot send to server");
    return false;
  }

  HTTPClient http;
  http.begin(serverUrl);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(HTTP_TIMEOUT_MS);

  Serial.println("📡 Sending to server: " + payload);
  int httpResponseCode = http.POST(payload);

  bool success = false;
  if (httpResponseCode > 0) {
    String response = http.getString();
    success = (httpResponseCode == 200);
  } else {
    Serial.printf("❌ Error sending to server: %s\n", http.errorToString(httpResponseCode).c_str());
  }

  http.end();
  return success;
}

void sendOfflinePayloads() {
  File file = SPIFFS.open("/offline_data.txt", FILE_READ);
  if (!file || file.size() == 0) {
    if (file) file.close();
    Serial.println("✅ No offline payloads to send.");
    return;
  }

  std::vector<String> lines;
  while (file.available()) {
    String line = file.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) lines.push_back(line);
  }
  file.close();

  if (lines.empty()) {
    Serial.println("No valid offline payloads found after reading file.");
    return;
  }

  Serial.printf("💾 Found %d offline payload(s). Sending to server...\n", lines.size());
  int sentCount = 0;
  for (const auto& line : lines) {
    if (WiFi.status() == WL_CONNECTED) {
      if (sendToServer(line)) {
        Serial.println("✅ Resent offline payload.");
        sentCount++;
        totalSent++;
        lastSuccessfullyConnectedOrSent = esp_timer_get_time();
      } else {
        Serial.println("❌ Failed to resend offline payload: " + line);
        break;
      }
    } else {
      Serial.println("❌ WiFi disconnected during offline payload send. Stopping resend.");
      break;
    }
    delay(100);
  }

  if (sentCount == lines.size()) {
    SPIFFS.remove("/offline_data.txt");
    Serial.printf("✅ Sent all %d offline payload(s) to server.\n", sentCount);
  } else {
    Serial.printf("⚠️ Only %d of %d offline payload(s) sent. Remaining data kept for next reconnect.\n", sentCount, lines.size());
    File outFile = SPIFFS.open("/offline_data.txt", FILE_WRITE);
    if (outFile) {
      for (size_t i = sentCount; i < lines.size(); ++i) {
        outFile.println(lines[i]);
      }
      outFile.close();
      Serial.println("Remaining offline payloads saved back to file.");
    } else {
      Serial.println("❌ Failed to reopen file to save remaining offline data!");
    }
  }
}

void WiFiEvent(arduino_event_id_t event) {
  static int wifiFailCount = 0;

  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      break;
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      wifiFailCount = 0;
      Serial.println("\n✅ WiFi connected!");
      // Send any offline data when WiFi reconnects
      if (offlinePayloadsExist()) {
        sendOfflinePayloads();
      }
      break;
    default:
      break;
  }
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  dht.begin();
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);

  WiFi.onEvent(WiFiEvent);

  if (!SPIFFS.begin(true)) {
    Serial.println("❌ SPIFFS Mount Failed! Offline storage will not work.");
    while (true);
  }

  Serial.print("📱 Starting WiFi connection to connect....");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  unsigned long wifiConnectStart = millis();
  Serial.print("\n⏳ Waiting for WiFi connection...");

  while (WiFi.status() != WL_CONNECTED && (millis() - wifiConnectStart < 30000)) {
    delay(500);
  }

  if (WiFi.status() == WL_CONNECTED) {
  } else {
    Serial.println("\n❌ WiFi connection failed after timeout!for 30 seconds.");
    Serial.println("😴 Going to deep sleep for 60 seconds due to WiFi failure...");
    delay(100);
    esp_sleep_enable_timer_wakeup(DEEP_SLEEP_DURATION_SEC * 1000000ULL);
    esp_deep_sleep_start();
  }

  syncTime();

  if (lastSuccessfullyConnectedOrSent == 0) {
      lastSuccessfullyConnectedOrSent = esp_timer_get_time();
  }
}

void loop() {
  static unsigned long lastQuickCheck = 0;
  
  // Quick non-blocking connection checks
  if (millis() - lastQuickCheck >= 100) {
    lastQuickCheck = millis();
    
    if (!WiFi.isConnected()) {
      tryConnectWiFi();
    }
  }

  // Time resync logic
  if (hasSyncedTime && (esp_timer_get_time() - lastNtpSyncTime) / 1000 >= NTP_SYNC_INTERVAL_MS) {
    Serial.print("⏳ Attempting NTP re-sync...");
    syncTime();
  }

  // Read sensors and encrypt data
  if (millis() - lastSensorReadTime >= SENSOR_READ_INTERVAL_MS) {
    lastSensorReadTime = millis();

    float temp = NAN, humi = NAN;
    float dist = getUltrasonicCM();

    bool dht_read_success = false;
    for (int i = 0; i < DHT_MAX_RETRIES; ++i) {
      temp = dht.readTemperature();
      humi = dht.readHumidity();
      if (!isnan(temp) && !isnan(humi)) {
        lastValidTemp = temp;
        lastValidHumi = humi;
        dht_read_success = true;
        break;
      }
      delay(DHT_RETRY_DELAY_MS);
    }

    if (!dht_read_success) {
      temp = isnan(temp) ? lastValidTemp : temp;
      humi = isnan(humi) ? lastValidHumi : humi;
    }

    char dist_str[10];
    snprintf(dist_str, sizeof(dist_str), (dist == -1.0) ? "null" : "%.1f", dist);
    snprintf(plaintext, sizeof(plaintext), "T:%.1f H:%.1f D:%.1f", temp, humi, dist);

    // Time and slot
    time_t raw_time = time(nullptr);
    struct tm current_tm;
    if (!getLocalTime(&current_tm, 100) || (1900 + current_tm.tm_year) < 2020) {
      if (hasSyncedTime) {
        current_tm = lastKnownGoodTimeinfo;
        raw_time = mktime(&current_tm);
      } else {
        raw_time = millis() / 1000;
        memset(&current_tm, 0, sizeof(current_tm));
      }
    } else {
      lastKnownGoodTimeinfo = current_tm;
      hasSyncedTime = true;
    }

    String slot = getTimeSlotString(current_tm);
    const char* ad_str = AD_STR;
    const uint8_t* ad = (const uint8_t*)ad_str;
    size_t adlen = strlen(ad_str);

    uint8_t key[16];
    deriveKeyFromTimeSlot(slot, key);

    uint8_t nonce[16];
    generateUniqueNonce(nonce);

    unsigned long enc_start = micros();
    int result = crypto_aead_encrypt(ciphertext, &clen,
                                     (const uint8_t*)plaintext, strlen(plaintext),
                                     ad, adlen,
                                     NULL, nonce, key);
    unsigned long enc_end = micros();

    if (result != 0 || clen < 16) {
      Serial.printf("❌ Encryption failed: code=%d, clen=%llu\n", result, clen);
      return;
    }

    size_t ct_len = clen - 16;
    char nonce_hex[33], tag_hex[33], ct_hex[2 * ct_len + 1];
    for (int i = 0; i < 16; ++i) sprintf(nonce_hex + i * 2, "%02X", nonce[i]);
    for (size_t i = 0; i < ct_len; ++i) sprintf(ct_hex + i * 2, "%02X", ciphertext[i]);
    for (size_t i = 0; i < 16; ++i) sprintf(tag_hex + i * 2, "%02X", ciphertext[ct_len + i]);

    char payload[350];
    snprintf(payload, sizeof(payload),
             "{\"timestamp\":%ld,\"nonce\":\"%s\",\"tag\":\"%s\",\"cipher\":\"%s\"}",
             raw_time, nonce_hex, tag_hex, ct_hex);

    String humanTime = String(1900 + current_tm.tm_year) + "-" + String(current_tm.tm_mon + 1) + "-" +
                       String(current_tm.tm_mday) + " " + String(current_tm.tm_hour) + ":" +
                       String(current_tm.tm_min) + ":" + String(current_tm.tm_sec);

    Serial.println("------------------------------------------------------------------------------");
    Serial.printf("🕒 HumanTime     : %s\n", humanTime.c_str());
    Serial.printf("📄 Plaintext     : %s\n", plaintext);
    Serial.printf("🧭 Timestamp     : %ld\n", raw_time);
    Serial.printf("📅 Slot          : %s\n", slot.c_str());
    Serial.printf("🆔 AD            : %s\n", ad_str);
    Serial.printf("🎲 Nonce         : %s\n", nonce_hex);
    Serial.printf("🏷️  Tag           : %s\n", tag_hex);
    Serial.printf("🔐 Cipher        : %s\n\n", ct_hex);  // Extra newline after Cipher
    Serial.printf("🔑 Derived Key   : ");
    printHexKey("", key, 16);
    Serial.printf("⏱️  Enc Time      : %lu µs\n", enc_end - enc_start);
    Serial.printf("🧠 Free Heap     : %u bytes\n", ESP.getFreeHeap());
    Serial.printf("📦 Payload Size  : %u bytes\n", strlen(payload));

    if (WiFi.status() == WL_CONNECTED) {
      if (sendToServer(payload)) {
        Serial.printf("✅ Server response: 200\n");  // ONLY status code
        Serial.printf("✅ Sent to server! Total sent: %d\n", ++totalSent);
        lastSuccessfullyConnectedOrSent = esp_timer_get_time();
      } else {
        Serial.println("❌ Server send failed, saving offline.");
        savePayloadOffline(payload);
      }
    } else {
      Serial.println("⚠️  WiFi disconnected, saving payload offline.");
      savePayloadOffline(payload);
    }

  }
    // 💡 Deep Sleep if WiFi has been disconnected for too long
  if (!WiFi.isConnected()) {
    if (wifiDisconnectedSince == 0) {
      wifiDisconnectedSince = esp_timer_get_time();  // Start disconnection timer
    } else if ((esp_timer_get_time() - wifiDisconnectedSince) >= DEEP_SLEEP_DISCONNECT_THRESHOLD_SEC * 1000000ULL) {
      Serial.printf("\n😴 WiFi disconnected for %lu seconds. Sleeping for %d seconds...\n",
                    (unsigned long)((esp_timer_get_time() - wifiDisconnectedSince) / 1000000ULL),
                    DEEP_SLEEP_DURATION_SEC);
      delay(100);
      esp_sleep_enable_timer_wakeup(DEEP_SLEEP_DURATION_SEC * 1000000ULL);
      esp_deep_sleep_start();
    }
  } else {
    wifiDisconnectedSince = 0;  // Reset timer on reconnect
  }
}
