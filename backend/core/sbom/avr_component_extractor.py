"""
AVR/MCU firmware component extractor for Phase 4.
Scans embedded strings in raw AVR binaries and maps them to known
Arduino/MCU libraries with CPE identifiers for NVD/OSV CVE lookup.
"""
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

# ─── Library signature → (string_pattern, name, vendor, cpe_product, osv_pkg, osv_eco, ver_re)
# vendor strings MUST match the NVD database exactly (verified against local SQLite)
ARDUINO_LIB_SIGNATURES = [
    # ── TLS / Crypto ─────────────────────────────────────────────────────────
    ("wolfSSL",      "wolfssl",       "wolfssl",      "wolfssl",
     None, None,     r"wolfSSL\s+(\d+[\.\d]+)"),
    ("mbedTLS",      "mbedtls",       "arm",          "mbed_tls",
     None, None,     r"mbedTLS\s+(\d+[\.\d]+)"),
    ("openssl",      "openssl",       "openssl",      "openssl",
     "openssl","Debian", r"[Oo]penssl\s+(\d+[\.\d]+[a-z]?)"),
    # NVD vendor for tinydtls is contiki-ng, not eclipse
    ("TinyDTLS",     "tinydtls",      "contiki-ng",   "tinydtls",
     None, None,     r"TinyDTLS\s+(\d+[\.\d]+)"),

    # ── RTOS ─────────────────────────────────────────────────────────────────
    ("FreeRTOS",     "freertos",      "amazon",       "freertos",
     None, None,     r"FreeRTOS\s+(\d+[\.\d]+)"),
    ("contiki",      "contiki",       "contiki-os",   "contiki",
     None, None,     None),

    # ── Networking ────────────────────────────────────────────────────────────
    # NVD vendor for lwip is lwip_project, not savannah
    ("lwIP",         "lwip",          "lwip_project", "lwip",
     None, None,     r"lwIP\s+(\d+[\.\d]+)"),
    ("uIP",          "uip",           "contiki",      "uip",
     None, None,     None),
    ("Mongoose",     "mongoose",      "cesanta",      "mongoose",
     None, None,     r"Mongoose\s+(\d+[\.\d]+)"),
    ("ENC28J60",     "enc28j60",      "microchip",    "enc28j60",
     None, None,     None),
    ("W5100",        "w5100",         "wiznet",       "w5100",
     None, None,     None),

    # ── MQTT ─────────────────────────────────────────────────────────────────
    ("Mosquitto",    "mosquitto",     "eclipse",      "mosquitto",
     None, None,     r"Mosquitto\s+(\d+[\.\d]+)"),
    ("PubSubClient", "pubsubclient",  "knolleary",    "pubsubclient",
     None, None,     r"PubSubClient[/\s]+(\d+[\.\d]+)"),
    ("MQTT:",        "mqtt-client",   "knolleary",    "pubsubclient",
     None, None,     None),

    # ── WiFi / Radio ─────────────────────────────────────────────────────────
    ("WiFiNINA",     "wifinina",      "arduino",      "wifinina",
     None, None,     r"WiFiNINA[/\s]+(\d+[\.\d]+)"),
    # NVD vendor for wpa_supplicant/hostapd is w1.fi
    ("wpa_supplicant","wpa_supplicant","w1.fi",       "wpa_supplicant",
     None, None,     None),
    ("hostapd",      "hostapd",       "w1.fi",        "hostapd",
     None, None,     None),
    ("NRF24",        "nrf24l01",      "nordic",       "nrf24l01",
     None, None,     None),
    ("ESP8266",      "esp8266",       "espressif",    "esp8266_sdk",
     None, None,     None),
    ("ESP32",        "esp32",         "espressif",    "esp-idf",
     None, None,     None),

    # ── Parsing / Serialization ───────────────────────────────────────────────
    ("ArduinoJson",  "arduinojson",   "bblanchon",    "arduinojson",
     None, None,     r"ArduinoJson[/\s]+(\d+[\.\d]+)"),
    ("cJSON",        "cjson",         "dave_gamble",  "cjson",
     None, None,     None),

    # ── avr-libc (always present on any AVR build) ────────────────────────────
    ("avr-gcc",      "avr-libc",      "nongnu",       "avr-libc",
     None, None,     r"avr-gcc\s+(\d+[\.\d]+)"),

    # ── Sensors ───────────────────────────────────────────────────────────────
    ("MPU-6050",     "mpu-6050",      "invensense",   "mpu-6050",
     None, None,     None),
    ("AT24C",        "at24c",         "atmel",        "at24c32",
     None, None,     None),

    # ── Security bypass markers (no CVE — go to CBOM/S108 only) ──────────────
    ("Secure boot DISABLED",          "secure-boot-off", None, None, None, None, None),
    ("Signature verification disabled","sig-verify-off",  None, None, None, None, None),
    ("Certificate pinning disabled",  "cert-pin-off",    None, None, None, None, None),
    ("UART console enabled",          "debug-uart",      None, None, None, None, None),
]

# Hardware chip → CPE mapping (for HBOM → CVE)
MCU_CPE_MAP = {
    "ATmega328P":  ("atmel",      "atmega328p",   "cpe:2.3:h:atmel:atmega328p:*:*:*:*:*:*:*:*"),
    "ATmega2560":  ("atmel",      "atmega2560",   "cpe:2.3:h:atmel:atmega2560:*:*:*:*:*:*:*:*"),
    "ESP8266":     ("espressif",  "esp8266",      "cpe:2.3:h:espressif:esp8266:*:*:*:*:*:*:*:*"),
    "ESP32":       ("espressif",  "esp32",        "cpe:2.3:h:espressif:esp32:*:*:*:*:*:*:*:*"),
    "NRF24L01":    ("nordic",     "nrf24l01",     "cpe:2.3:h:nordic:nrf24l01:*:*:*:*:*:*:*:*"),
    "ENC28J60":    ("microchip",  "enc28j60",     "cpe:2.3:h:microchip:enc28j60:*:*:*:*:*:*:*:*"),
    "MPU-6050":    ("invensense", "mpu_6050",     "cpe:2.3:h:invensense:mpu-6050:*:*:*:*:*:*:*:*"),
    "AT24C32":     ("atmel",      "at24c32",      "cpe:2.3:h:atmel:at24c32:*:*:*:*:*:*:*:*"),
}

# Hardware detection patterns in strings
HW_PATTERNS = [
    (r'\bATmega328P?\b',   "ATmega328P",  "Atmel/Microchip", "Microcontroller"),
    (r'\bATmega2560\b',    "ATmega2560",  "Atmel/Microchip", "Microcontroller"),
    (r'\bATtiny85\b',      "ATtiny85",    "Atmel/Microchip", "Microcontroller"),
    (r'\bESP8266\b',       "ESP8266",     "Espressif",       "WiFi SoC"),
    (r'\bESP32\b',         "ESP32",       "Espressif",       "WiFi/BT SoC"),
    (r'\bNRF24',           "NRF24L01",    "Nordic Semi",     "Radio/RF"),
    (r'\bMPU.?6050\b',     "MPU-6050",    "InvenSense",      "Sensor/IMU"),
    (r'\bAT24C\d+\b',      "AT24C32",     "Atmel",           "EEPROM"),
    (r'\bENC28J60\b',      "ENC28J60",    "Microchip",       "Ethernet"),
    (r'\bW5100\b',         "W5100",       "WIZnet",          "Ethernet"),
    (r'\bBME280\b',        "BME280",      "Bosch",           "Sensor/Env"),
    (r'\bDS18B20\b',       "DS18B20",     "Dallas/Maxim",    "Sensor/Temp"),
    (r'\bCC2500\b',        "CC2500",      "Texas Instruments","Radio/RF"),
]

# Crypto markers → (algorithm, category, strength)
CRYPTO_MARKERS = [
    (r'\bAES.?128\b',   "AES-128",   "symmetric",  "strong"),
    (r'\bAES.?256\b',   "AES-256",   "symmetric",  "strong"),
    (r'\bDES\b',        "DES",       "symmetric",  "insecure"),
    (r'\b3DES\b',       "3DES",      "symmetric",  "weak"),
    (r'\bRC4\b',        "RC4",       "symmetric",  "insecure"),
    (r'\bMD5\b',        "MD5",       "hash",       "weak"),
    (r'\bSHA.?1\b',     "SHA-1",     "hash",       "weak"),
    (r'\bSHA.?256\b',   "SHA-256",   "hash",       "strong"),
    (r'\bSSLv3\b',      "SSLv3",     "protocol",   "insecure"),
    (r'\bTLS.?1\.0\b',  "TLS 1.0",  "protocol",   "insecure"),
    (r'\bTLS.?1\.2\b',  "TLS 1.2",  "protocol",   "acceptable"),
    (r'\bXOR\b|xor_crypt', "XOR",   "symmetric",  "insecure"),
    (r'\bRSA\b',        "RSA",       "asymmetric", "acceptable"),
    (r'\bECDSA\b',      "ECDSA",     "asymmetric", "strong"),
]


def extract_strings(binary_path: str, min_len: int = 5) -> List[str]:
    try:
        r = subprocess.run(
            ["strings", f"-n{min_len}", binary_path],
            capture_output=True, text=True, timeout=15
        )
        return r.stdout.strip().splitlines()
    except Exception as e:
        logger.warning(f"strings failed on {binary_path}: {e}")
        return []


def detect_avr_components(
    binary_paths: List[str],
    hbom_components: List[Dict],
    log_cb=None,
) -> List[Dict]:
    if log_cb is None:
        log_cb = logger.info

    log_cb("[AVR-SBOM] Scanning AVR binaries for library signatures…")

    all_strings: List[str] = []
    for bp in binary_paths:
        if Path(bp).exists():
            s = extract_strings(bp)
            all_strings.extend(s)
            log_cb(f"[AVR-SBOM] {Path(bp).name}: {len(s)} strings extracted")

    combined = "\n".join(all_strings)
    components: List[Dict] = []
    seen: set = set()

    # avr-libc always present on any AVR build
    _add(components, seen, log_cb,
         name="avr-libc", vendor="nongnu", product="avr-libc",
         version="2.0.0", source="avr-implicit",
         cpe="cpe:2.3:a:nongnu:avr-libc:2.0.0:*:*:*:*:*:*:*",
         osv_pkg=None, osv_eco=None)

    # Scan all signatures
    for (sig, name, vendor, product, osv_pkg, osv_eco, ver_re) in ARDUINO_LIB_SIGNATURES:
        if name in seen:
            continue
        if sig.lower() not in combined.lower():
            continue

        # Extract version
        version = "unknown"
        if ver_re:
            m = re.search(ver_re, combined, re.IGNORECASE)
            if m:
                try:
                    version = m.group(1)
                except IndexError:
                    pass

        if version == "unknown":
            # Try to find a version number on the same line as the sig
            for line in all_strings:
                if sig.lower() in line.lower():
                    vm = re.search(r'(\d+\.\d+[\.\d]*)', line)
                    if vm:
                        version = vm.group(1)
                        break

        cpe = (f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
               if vendor and product else "")

        _add(components, seen, log_cb,
             name=name, vendor=vendor or "", product=product or "",
             version=version, source="avr-string-scan",
             cpe=cpe, osv_pkg=osv_pkg, osv_eco=osv_eco)

    # MCU from HBOM
    for hw in hbom_components:
        hw_name = hw.get("name", "")
        if hw_name in MCU_CPE_MAP and hw_name not in seen:
            v, p, cpe_s = MCU_CPE_MAP[hw_name]
            _add(components, seen, log_cb,
                 name=hw_name, vendor=v, product=p,
                 version="*", source="hbom",
                 cpe=cpe_s, osv_pkg=None, osv_eco=None)

    # Firmware identity
    fw_name = "custom-avr-firmware"
    fw_ver  = "unknown"
    for s in all_strings:
        m = re.search(r'([A-Za-z][A-Za-z0-9\-]{3,20})[-_]IoT|([A-Za-z][A-Za-z0-9\-]{3,20})-Firmware', s)
        if m:
            fw_name = (m.group(1) or m.group(2)).lower()
        vm = re.search(r'FW[-_]?(\d+[\.\d\-\w]+)', s, re.IGNORECASE)
        if vm:
            fw_ver = vm.group(1)
    if fw_name not in seen:
        _add(components, seen, log_cb,
             name=fw_name, vendor="", product="",
             version=fw_ver, source="avr-firmware-id",
             cpe="", osv_pkg=None, osv_eco=None)

    log_cb(f"[AVR-SBOM] Total: {len(components)} components detected")
    return components


def detect_avr_hardware(binary_paths: List[str], log_cb=None) -> List[Dict]:
    """Detect hardware components from embedded strings for HBOM."""
    if log_cb is None:
        log_cb = logger.info

    all_strings = []
    for bp in binary_paths:
        if Path(bp).exists():
            all_strings.extend(extract_strings(bp))

    combined = "\n".join(all_strings)
    hw_components = []
    seen = set()

    for pattern, name, mfr, ctype in HW_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE) and name not in seen:
            seen.add(name)
            cpe = MCU_CPE_MAP.get(name, (None, None, ""))[2]
            hw_components.append({
                "bom_ref":        str(__import__("uuid").uuid4()),
                "component_type": ctype,
                "name":           name,
                "manufacturer":   mfr,
                "model":          "",
                "version":        "*",
                "description":    f"Detected via string scan",
                "source":         "avr-string-scan",
                "cpe":            cpe,
            })
            log_cb(f"[HBOM] HW detected: {name} ({mfr}) — CPE: {cpe or 'n/a'}")

    return hw_components


def detect_avr_crypto(binary_paths: List[str], log_cb=None) -> List[Dict]:
    """Detect cryptographic algorithm usage from embedded strings for CBOM."""
    if log_cb is None:
        log_cb = logger.info

    all_strings = []
    for bp in binary_paths:
        if Path(bp).exists():
            all_strings.extend(extract_strings(bp))

    combined = "\n".join(all_strings)
    crypto_components = []
    seen_algos = set()

    for pattern, algo, category, strength in CRYPTO_MARKERS:
        if algo in seen_algos:
            continue
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            seen_algos.add(algo)
            # Find the line for context
            context_line = next(
                (l.strip() for l in all_strings
                 if re.search(pattern, l, re.IGNORECASE)), ""
            )
            crypto_components.append({
                "bom_ref":    str(__import__("uuid").uuid4()),
                "algorithm":  algo,
                "category":   category,
                "strength":   strength,
                "source_file": "flash.bin",
                "context":    context_line[:100],
                "primitive":  algo,
            })
            log_cb(f"[CBOM] Crypto: {algo} ({category}/{strength})")

    return crypto_components


def _add(components, seen, log_cb, *, name, vendor, product,
         version, source, cpe, osv_pkg, osv_eco):
    seen.add(name)
    components.append({
        "name":           name,
        "version":        version,
        "vendor":         vendor,
        "cpe":            cpe,
        "purl":           f"pkg:generic/{vendor}/{name}@{version}" if vendor else "",
        "license":        "NOASSERTION",
        "component_type": "firmware" if not vendor else "library",
        "source_path":    source,
        "osv_package":    osv_pkg,
        "osv_ecosystem":  osv_eco,
    })
    log_cb(f"[AVR-SBOM] + {name:25} v{version:12} CPE={cpe[:50] if cpe else 'n/a'}")
