/*
 * vulnerable_test_firmware.ino
 *
 * IIFVDCAS Scanner Test Firmware — intentionally insecure.
 * Purpose: validate that Phase 3 (static analysis), Phase 4 (SBOM/HBOM/CBOM),
 * and Phase 5 (CVE mapping) all fire correctly against a real Arduino device.
 *
 * Flash to Arduino UNO (ATmega328P):
 *   arduino-cli compile --fqbn arduino:avr:uno .
 *   arduino-cli upload  --fqbn arduino:avr:uno --port /dev/ttyACM0 .
 *
 * DELIBERATELY INSECURE — do NOT deploy in production.
 */

#include <Arduino.h>
#include <EEPROM.h>
#include <Wire.h>
#include <SPI.h>

// ─────────────────────────────────────────────────────────────────────────────
// Library version identifiers embedded as strings so the SBOM scanner
// can detect them and look up CVEs in NVD/OSV.
//
// These are REAL library versions that have KNOWN CVEs:
//   wolfSSL 4.0.0  → CVE-2019-11873 (CVSS 9.8 CRITICAL) — heap buffer overflow
//   FreeRTOS 10.0.0→ CVE-2021-31571 (CVSS 9.8 CRITICAL) — stack overflow
//   lwIP 2.0.3     → CVE-2020-22283 (CVSS 7.5 HIGH)     — out-of-bounds read
//   Mongoose 6.14  → CVE-2018-20353 (CVSS 9.8 CRITICAL) — use-after-free
//   TinyDTLS 0.9.0 → CVE-2021-42141 (CVSS 9.8 CRITICAL) — remote code execution
// ─────────────────────────────────────────────────────────────────────────────
const char* LIB_wolfssl     = "wolfSSL 4.0.0";
const char* LIB_freertos    = "FreeRTOS 10.0.0";
const char* LIB_lwip        = "lwIP 2.0.3";
const char* LIB_mongoose    = "Mongoose 6.14";
const char* LIB_tinydtls    = "TinyDTLS 0.9.0";
const char* LIB_mosquitto   = "Mosquitto 1.4.15";

// ─── Hardware identifiers (HBOM) ─────────────────────────────────────────────
// These strings let the scanner populate the Hardware Bill of Materials.
const char* HW_mcu          = "ATmega328P";
const char* HW_radio        = "NRF24L01";
const char* HW_sensor       = "MPU-6050";
const char* HW_eeprom       = "AT24C32";
const char* HW_ethernet     = "ENC28J60";

// ─── Firmware identity ────────────────────────────────────────────────────────
const char* FW_name         = "SmartHome-IoT";
const char* FW_version      = "FW-2.1.0-debug";
const char* FW_build        = "built with avr-gcc 7.3.0";

// ─────────────────────────────────────────────────────────────────────────────
// S45/S107: Hardcoded credentials (Phase 3 detects these)
// ─────────────────────────────────────────────────────────────────────────────
const char* WIFI_SSID       = "LabWiFi";
const char* WIFI_PASS       = "SuperSecretPass123";
const char* MQTT_BROKER     = "192.168.1.50";
const char* MQTT_PORT       = "1883";
const char* MQTT_USER       = "admin";
const char* MQTT_PASS       = "admin123";
const char* API_TOKEN       = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const char* ADMIN_HASH      = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LzTfAkJnSB2";
const char* AWS_KEY         = "AKIAIOSFODNN7EXAMPLE";
const char* AWS_SECRET      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// ─────────────────────────────────────────────────────────────────────────────
// S108: Insecure protocol URLs (HTTP instead of HTTPS)
// ─────────────────────────────────────────────────────────────────────────────
const char* OTA_SERVER      = "http://iot-update.local/fw.bin";
const char* CONFIG_SERVER   = "http://192.168.1.50/config.json";
const char* TELEMETRY_URL   = "http://api.smartthings.com/v1/data";

// ─────────────────────────────────────────────────────────────────────────────
// CBOM: Crypto algorithm markers — weak/insecure ones for CBOM detection
// ─────────────────────────────────────────────────────────────────────────────
const char* CRYPTO_info     = "AES-128 DES MD5 SHA-1 RC4 SSLv3 TLS1.0";

// ─────────────────────────────────────────────────────────────────────────────
// Weak crypto implementation — XOR "encryption"
// CBOM scanner flags this as insecure
// ─────────────────────────────────────────────────────────────────────────────
void xor_crypt(uint8_t* buf, uint16_t len, uint8_t key) {
    for (uint16_t i = 0; i < len; i++) buf[i] ^= key;
}

// MD5 stub — weak hash for credential storage
void store_credential_md5(const char* cred) {
    // Using MD5 for password hashing — insecure, detectable
    Serial.print("[CRYPTO] MD5 hash: ");
    Serial.println(cred);
}

// DES stub — deprecated symmetric cipher
void des_encrypt_stub(uint8_t* block) {
    // DES encryption — 56-bit key, broken since 1997
    xor_crypt(block, 8, 0xDE);
}

// ─────────────────────────────────────────────────────────────────────────────
// S108: Debug backdoor menu
// ─────────────────────────────────────────────────────────────────────────────
void debug_menu() {
    Serial.println(F("==== DEBUG MENU ===="));
    Serial.println(F("1. Dump WiFi creds"));
    Serial.println(F("2. Dump token"));
    Serial.println(F("3. Print config"));
    Serial.println(F("4. Dump EEPROM"));
    Serial.println(F("5. Factory reset"));

    if (!Serial.available()) return;
    char cmd = Serial.read();

    if (cmd == '1') {
        Serial.print(F("SSID: ")); Serial.println(WIFI_SSID);
        Serial.print(F("PASS: ")); Serial.println(WIFI_PASS);
    }
    if (cmd == '2') {
        Serial.print(F("TOKEN: ")); Serial.println(API_TOKEN);
        Serial.print(F("AWS: "));   Serial.println(AWS_KEY);
    }
    if (cmd == '3') {
        Serial.print(F("MQTT: "));  Serial.println(MQTT_BROKER);
        Serial.print(F("OTA: "));   Serial.println(OTA_SERVER);
    }
    if (cmd == '4') {
        for (int i = 0; i < 64; i++) {
            Serial.print(EEPROM.read(i), HEX);
            Serial.print(' ');
        }
        Serial.println();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OTA update — unsigned, over HTTP, no certificate pinning
// ─────────────────────────────────────────────────────────────────────────────
void ota_check() {
    Serial.print(F("[OTA] Connecting to: "));
    Serial.println(OTA_SERVER);
    Serial.println(F("[OTA] WARNING: Signature verification disabled"));
    Serial.println(F("[OTA] WARNING: TLS certificate validation disabled"));
    Serial.println(F("[OTA] Update available: v2.2.0"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Boot sequence
// ─────────────────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    while (!Serial) delay(10);

    // Identity strings — SBOM scanner reads these
    Serial.println(FW_name);
    Serial.println(FW_version);
    Serial.println(FW_build);

    // Library version strings — CPE/CVE lookup bait
    Serial.println(LIB_wolfssl);
    Serial.println(LIB_freertos);
    Serial.println(LIB_lwip);
    Serial.println(LIB_mongoose);
    Serial.println(LIB_tinydtls);
    Serial.println(LIB_mosquitto);

    // Hardware strings — HBOM detection
    Serial.print(F("MCU: "));      Serial.println(HW_mcu);
    Serial.print(F("Radio: "));    Serial.println(HW_radio);
    Serial.print(F("Sensor: "));   Serial.println(HW_sensor);
    Serial.print(F("EEPROM: "));   Serial.println(HW_eeprom);
    Serial.print(F("Ethernet: ")); Serial.println(HW_ethernet);

    // Crypto inventory string — CBOM detection
    Serial.print(F("Crypto: "));   Serial.println(CRYPTO_info);

    // Security bypass markers — S108 backdoor detection
    Serial.println(F("[BOOT] Secure boot DISABLED"));
    Serial.println(F("[BOOT] Signature verification disabled"));
    Serial.println(F("[DEBUG] UART console enabled"));
    Serial.println(F("[DEBUG] Boot delay active"));
    Serial.println(F("[SECURITY] Certificate pinning disabled"));
    Serial.println(F("[SECURITY] Firmware encryption disabled"));

    // Store a credential with weak hash
    store_credential_md5(WIFI_PASS);

    Wire.begin();
    SPI.begin();
}

// ─────────────────────────────────────────────────────────────────────────────
// Main loop
// ─────────────────────────────────────────────────────────────────────────────
void loop() {
    ota_check();
    debug_menu();

    // Repeat library version strings periodically so strings tool finds them
    Serial.println(LIB_wolfssl);
    Serial.println(LIB_freertos);
    Serial.println(LIB_lwip);

    // MQTT connection (cleartext, no TLS)
    Serial.print(F("MQTT: "));   Serial.println(MQTT_BROKER);
    Serial.print(F("PORT: "));   Serial.println(MQTT_PORT);
    Serial.print(F("DEBUG: "));  Serial.println("1");

    delay(10000);
}
