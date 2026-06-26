/*
 * vulnerable_firmware_esp32.ino
 *
 * IIFVDCAS Scanner Test Firmware — ESP32, intentionally insecure.
 * Purpose: validate Phases 1-7 against a real ESP32-D0WD device with a
 * genuine WiFi/lwIP/FreeRTOS stack. Unlike the bare-metal AVR test,
 * network-based and OS-level CVEs SHOULD be triaged as AFFECTED here,
 * since ESP32 has real WiFi hardware, real lwIP TCP/IP stack, and runs
 * real FreeRTOS as its actual operating system.
 *
 * Flash:
 *   arduino-cli compile --fqbn esp32:esp32:esp32 vulnerable_firmware_esp32
 *   arduino-cli upload  --fqbn esp32:esp32:esp32 -p /dev/ttyUSB0 vulnerable_firmware_esp32
 *
 * DELIBERATELY INSECURE — for IIFVDCAS scanner testing ONLY.
 */

#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <esp_system.h>
#include <esp_wifi.h>

// ─────────────────────────────────────────────────────────────────────────────
// Library/component version strings embedded so the SBOM scanner can detect
// them and map them to NVD/OSV CVEs. ESP32 genuinely ships these components
// (ESP-IDF bundles FreeRTOS, lwIP, mbedTLS for real — these are not fake
// strings like the AVR test, they reflect the actual underlying SDK).
//
//   ESP-IDF 4.4.1   -> CVE-2023-41108 (BluFi auth bypass), multiple WiFi CVEs
//   mbedTLS 2.16.0  -> several heap overflow / timing CVEs (CVSS up to 9.8)
//   lwIP 2.1.2      -> CVE-2020-22283 (OOB read), known DoS issues
//   FreeRTOS 10.4.3 -> CVE-2021-31571 (stack overflow), task isolation issues
//   PubSubClient 2.7-> known buffer overflow in MQTT topic parsing
//   ArduinoJson 5.13.3 -> known buffer overflow on malformed JSON
// ─────────────────────────────────────────────────────────────────────────────
const char* SDK_esp_idf      = "ESP-IDF 4.4.1";
const char* LIB_mbedtls      = "mbedTLS 2.16.0";
const char* LIB_lwip         = "lwIP 2.1.2";
const char* LIB_freertos     = "FreeRTOS 10.4.3";
const char* LIB_pubsubclient = "PubSubClient 2.7";
const char* LIB_arduinojson  = "ArduinoJson 5.13.3";
const char* LIB_wifimanager  = "WiFiManager 0.16.0";

// ─── Hardware identifiers (HBOM) ──────────────────────────────────────────────
const char* HW_chip          = "ESP32-D0WD-V3";
const char* HW_flash         = "GD25Q32 4MB SPI Flash";
const char* HW_sensor        = "BME280";
const char* HW_rtc           = "DS3231";

// ─── Firmware identity ─────────────────────────────────────────────────────────
const char* FW_name          = "SmartCam-ESP32";
const char* FW_version       = "FW-3.4.1-debug";
const char* FW_build         = "built with esp-idf 4.4.1 / xtensa-esp32-elf-gcc";

// ─────────────────────────────────────────────────────────────────────────────
// S45/S107: Hardcoded credentials (Phase 3 detects these)
// ─────────────────────────────────────────────────────────────────────────────
const char* WIFI_SSID        = "OfficeWiFi-5G";
const char* WIFI_PASS        = "Password@2024!";
const char* MQTT_BROKER      = "192.168.1.100";
const char* MQTT_PORT        = "1883";
const char* MQTT_USER        = "esp32cam";
const char* MQTT_PASS        = "camera123";
const char* API_TOKEN        = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.esp32cam";
const char* CLOUD_API_KEY    = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBc";
const char* ADMIN_PASS_HASH  = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LzTfAkJnSB2";
const char* DB_CONNECTION    = "mysql://admin:Sup3rS3cr3t@10.0.0.50:3306/cameradb";

// ─────────────────────────────────────────────────────────────────────────────
// S108: Insecure protocol URLs (HTTP instead of HTTPS)
// ─────────────────────────────────────────────────────────────────────────────
const char* OTA_SERVER       = "http://firmware-update.local/esp32cam/fw.bin";
const char* CONFIG_SERVER    = "http://192.168.1.100/api/config.json";
const char* TELEMETRY_URL    = "http://analytics.smartcam-vendor.com/v1/upload";
const char* VIDEO_STREAM_URL = "http://192.168.1.100:8080/stream";  // unencrypted video!

// ─────────────────────────────────────────────────────────────────────────────
// CBOM: Crypto algorithm markers
// ─────────────────────────────────────────────────────────────────────────────
const char* CRYPTO_info      = "AES-128-CBC DES3 MD5 SHA1 RC4 SSLv3 TLS1.0 TLS1.1";

Preferences prefs;
WiFiServer debugServer(23);   // telnet-style debug port — backdoor

// ─────────────────────────────────────────────────────────────────────────────
// Weak crypto — XOR "encryption" for stored credentials
// ─────────────────────────────────────────────────────────────────────────────
void xor_crypt(uint8_t* buf, size_t len, uint8_t key) {
  for (size_t i = 0; i < len; i++) buf[i] ^= key;
}

void store_credential_md5(const char* cred) {
  Serial.print("[CRYPTO] MD5 hash stored for: ");
  Serial.println(cred);
}

// ─────────────────────────────────────────────────────────────────────────────
// S108: Debug backdoor over telnet (port 23) — real network-reachable backdoor
// ─────────────────────────────────────────────────────────────────────────────
void handle_debug_client(WiFiClient& client) {
  client.println("==== ESP32-CAM DEBUG CONSOLE ====");
  client.println("1. Dump WiFi credentials");
  client.println("2. Dump API tokens");
  client.println("3. Dump DB connection string");
  client.println("4. Reboot device");
  client.println("5. Disable secure boot check");

  if (client.available()) {
    char cmd = client.read();
    switch (cmd) {
      case '1':
        client.print("SSID: "); client.println(WIFI_SSID);
        client.print("PASS: "); client.println(WIFI_PASS);
        break;
      case '2':
        client.print("API_TOKEN: "); client.println(API_TOKEN);
        client.print("CLOUD_KEY: "); client.println(CLOUD_API_KEY);
        break;
      case '3':
        client.print("DB: "); client.println(DB_CONNECTION);
        break;
      case '4':
        client.println("[BOOT] Rebooting...");
        ESP.restart();
        break;
      case '5':
        client.println("[SECURITY] Secure boot check DISABLED for this session");
        break;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// OTA update — unsigned, over HTTP, no certificate pinning
// ─────────────────────────────────────────────────────────────────────────────
void ota_check() {
  Serial.print("[OTA] Connecting to: ");
  Serial.println(OTA_SERVER);
  Serial.println("[OTA] WARNING: Signature verification disabled");
  Serial.println("[OTA] WARNING: TLS certificate validation disabled");
  Serial.println("[OTA] WARNING: Rollback protection disabled");
  Serial.println("[OTA] Update available: v3.5.0");
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Identity strings — SBOM scanner reads these
  Serial.println(FW_name);
  Serial.println(FW_version);
  Serial.println(FW_build);
  Serial.println(SDK_esp_idf);

  // Library version strings — CPE/CVE lookup bait (real ESP-IDF components)
  Serial.println(LIB_mbedtls);
  Serial.println(LIB_lwip);
  Serial.println(LIB_freertos);
  Serial.println(LIB_pubsubclient);
  Serial.println(LIB_arduinojson);
  Serial.println(LIB_wifimanager);

  // Hardware strings — HBOM detection
  Serial.print("Chip: ");    Serial.println(HW_chip);
  Serial.print("Flash: ");   Serial.println(HW_flash);
  Serial.print("Sensor: ");  Serial.println(HW_sensor);
  Serial.print("RTC: ");     Serial.println(HW_rtc);

  // Crypto inventory — CBOM detection
  Serial.print("Crypto: ");  Serial.println(CRYPTO_info);

  // Security bypass markers — S108 backdoor detection
  Serial.println("[BOOT] Secure boot DISABLED");
  Serial.println("[BOOT] Flash encryption DISABLED");
  Serial.println("[BOOT] Signature verification disabled");
  Serial.println("[DEBUG] Telnet debug console enabled on port 23");
  Serial.println("[SECURITY] Certificate pinning disabled");
  Serial.println("[SECURITY] JTAG debugging interface enabled");

  store_credential_md5(WIFI_PASS);

  // Real WiFi connection attempt (genuinely uses the hardcoded creds)
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  // Start the real backdoor telnet server (network-reachable!)
  debugServer.begin();
  Serial.println("[DEBUG] Debug server listening on :23");

  prefs.begin("camcfg", false);
  prefs.putString("mqtt_pass", MQTT_PASS);   // stored in NVS, retrievable
}

void loop() {
  ota_check();

  // Repeat library version strings periodically so strings tool finds them
  Serial.println(LIB_mbedtls);
  Serial.println(LIB_freertos);
  Serial.println(LIB_lwip);

  Serial.print("MQTT: "); Serial.println(MQTT_BROKER);
  Serial.print("PORT: "); Serial.println(MQTT_PORT);
  Serial.print("STREAM: "); Serial.println(VIDEO_STREAM_URL);

  WiFiClient debugClient = debugServer.available();
  if (debugClient) {
    handle_debug_client(debugClient);
    debugClient.stop();
  }

  delay(8000);
}
