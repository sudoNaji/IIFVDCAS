<div align="center">

<img src="https://img.shields.io/badge/IIFVDCAS-IoT%20Firmware%20Security-4f46e5?style=for-the-badge&logo=shield&logoColor=white" alt="IIFVDCAS"/>

# IIFVDCAS
### IoT Integrated Firmware Vulnerability Detection & Compliance Analysis System

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB?style=flat-square&logo=react&logoColor=black)](https://reactjs.org)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.5-00a0e1?style=flat-square)](https://cyclonedx.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)]()

**A full-stack firmware security assessment platform for IoT devices.**  
Automated 7-phase pipeline: device detection → firmware extraction → static analysis → SBOM/HBOM/CBOM → CVE mapping → VEX risk triage → compliance report (PDF).

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [Pipeline](#-7-phase-pipeline) · [Hardware](#-hardware-support) · [Status](#-project-status)

</div>

---

## 🎯 What is IIFVDCAS?

IIFVDCAS is a security research platform built for IoT firmware analysis. Connect an Arduino or ESP32, click **Extract Firmware**, and within minutes receive:

- A **Software/Hardware/Crypto Bill of Materials** (SBOM/HBOM/CBOM) in CycloneDX 1.5 format
- **CVE mapping** against 186,000+ NVD vulnerabilities with EPSS exploitation probability scores
- **VEX risk analysis** that determines which CVEs are actually exploitable in your specific firmware context
- A **compliance gap report** (ETSI EN 303 645, EU CRA 2024, OWASP IoT Top 10) with a downloadable PDF

Built by a **Final Year BS Cybersecurity student at UMT Lahore** as a portfolio project demonstrating end-to-end DevSecOps engineering.

---

## ✨ Features

| Feature | Details |
|---|---|
| **7-phase automated pipeline** | Device → Extraction → Static → SBOM → CVE → VEX → Report |
| **Live WebSocket progress** | Real-time log streaming for every phase |
| **AVR + ESP32 support** | avrdude for Arduino, esptool with auto-retry for ESP32 |
| **186k CVE local index** | SQLite NVD index with 5ms lookup (vs 1s+ REST API) |
| **OSV + NVD dual source** | Batch OSV API as secondary lookup for npm/embedded packages |
| **CycloneDX 1.5 VEX** | Standards-compliant VEX document output |
| **Architecture-aware triage** | AVR bare-metal gets different VEX rules than ESP32 (real network stack) |
| **PDF compliance report** | ReportLab A4 report: cover page, CVE table, gap matrix, remediation plan |
| **No vendor lock-in** | Runs entirely offline — NVD index is local, no API keys required by default |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    IIFVDCAS Frontend (React + Vite)             │
│  Dashboard · P1 · P2 · P3 · P4 · P5 · P6 · P7 · AI Settings   │
└────────────────────────┬────────────────────────────────────────┘
                         │  REST + WebSocket
┌────────────────────────▼────────────────────────────────────────┐
│                    FastAPI Backend (Python 3.11)                 │
│                                                                  │
│  Phase 1 │ device_detection/   USB/serial scan, 17 fingerprints │
│  Phase 2 │ firmware_extraction/ esptool + avrdude + binwalk      │
│  Phase 3 │ static_analysis/    checksec, S13, S45, S108, bandit  │
│  Phase 4 │ sbom/               CycloneDX SBOM + HBOM + CBOM     │
│  Phase 5 │ cve_mapping/        NVD SQLite + OSV + EPSS + KEV    │
│  Phase 6 │ vex_engine/         7-rule triage, risk scorer        │
│  Phase 7 │ compliance/         ETSI/CRA/OWASP gap check + PDF   │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
          ┌────────────────────────┼──────────────────────┐
          │                        │                       │
    ┌─────▼──────┐        ┌───────▼───────┐      ┌───────▼────────┐
    │ NVD SQLite │        │  OSV batch API │      │ esptool/avrdude│
    │  291 MB    │        │  api.osv.dev   │      │  /dev/ttyUSB0  │
    │  186k CVEs │        │  (free, no key)│      │  /dev/ttyACM0  │
    └────────────┘        └───────────────┘      └────────────────┘
```

**Tech stack:**
- **Backend:** FastAPI, Python 3.11, SQLite, ReportLab, asyncio
- **Frontend:** React 18, Vite, TailwindCSS, Lucide icons
- **Standards:** CycloneDX 1.5, OpenVEX, ETSI EN 303 645, EU CRA 2024, OWASP IoT Top 10
- **Tools:** esptool v5.3, avrdude, binwalk, unblob, checksec, bandit, avr-objdump

---

## 🚀 Quick Start

### Prerequisites

```bash
# Python 3.11+, Node.js 18+
pip install fastapi uvicorn python-multipart aiofiles reportlab anthropic requests

# Security tools (Kali Linux / Ubuntu)
sudo apt install -y binwalk checksec avrdude avr-binutils

# esptool for ESP32
pip install esptool
```

### Installation

```bash
git clone https://github.com/sudoNaji/IIFVDCAS.git
cd IIFVDCAS

# Frontend dependencies
cd frontend && npm install && cd ..

# Build the NVD local index (one-time, ~30 min, needs NVD feeds)
# Download NVD data feeds first — see docs/NVD_SETUP.md
python3 backend/core/cve_mapping/build_nvd_index.py
```

### Run

```bash
./scripts/dev.sh
```

This starts:
- FastAPI backend on `http://localhost:8000`
- React frontend on `http://localhost:5173`

Open `http://localhost:5173` in your browser.

---

## 🔬 7-Phase Pipeline

### Phase 1 — Device Detection
Scans USB/serial ports using `udevadm`, `lsusb`, and vendor ID matching against 17 device fingerprints. Identifies Arduino (ATmega), ESP32 (CP2102/CH340), Raspberry Pi, and custom MCU boards. Also supports network scanning via nmap.

```
Detected: CP2102 USB to UART Bridge → ESP32-D0WD-V3 on /dev/ttyUSB0
```

### Phase 2 — Firmware Extraction
**ESP32/ESP8266:** esptool with automatic 4-attempt retry ladder:
```
Attempt 1: stub flasher, 460800 baud
Attempt 2: stub flasher, 230400 baud  
Attempt 3: stub flasher, 115200 baud
Attempt 4: --no-stub (ROM bootloader), 115200 baud  ← fixes "Corrupt data" errors
```

**AVR/Arduino:** avrdude reads flash + optional EEPROM. Both tools save raw binary to `/tmp/iifvdcas_firmware_store/`.

Post-extraction pipeline runs binwalk → unblob → filesystem carving for squashfs, cramfs, JFFS2, UBI, ext2/3/4.

### Phase 3 — Static Analysis
Runs 8 EMBA-inspired analysis scripts:

| Script | Detects |
|---|---|
| S12 | NX, PIE, RELRO, stack canary (checksec) |
| S13 | Unsafe functions: strcpy, gets, sprintf, memcpy |
| S20 | Shell script issues (shellcheck) + Python issues (bandit) |
| S45/S107 | Hardcoded credentials, API keys, AWS secrets, password hashes |
| S60 | Expired/weak TLS certificates, self-signed certs |
| S85 | SSH key issues, weak ciphers |
| S108 | Embedded strings: backdoors, debug menus, insecure protocol URLs |
| AVR | avr-objdump disassembly, interrupt vectors, stack depth analysis |

**Output:** Risk score 0–100, per-finding severity (CRITICAL/HIGH/MEDIUM/LOW).

### Phase 4 — SBOM / HBOM / CBOM
Generates three CycloneDX 1.5 bills of materials:

- **SBOM** — Software components detected from binary strings (wolfSSL, FreeRTOS, lwIP, Mongoose, TinyDTLS, Mosquitto, etc.) with CPE identifiers for NVD lookup
- **HBOM** — Hardware components (ATmega328P, ENC28J60, MPU-6050, ESP32-D0WD-V3, BME280) with manufacturer and model
- **CBOM** — Cryptographic assets (AES-128, DES, MD5, SHA-1, RC4, SSLv3) with strength ratings (strong/acceptable/weak/insecure)

**Architecture detection:** ESP32 firmware (magic byte `0xe9` + `esp-idf`/`xtensa` strings) is detected before the AVR fallback, ensuring correct VEX triage rules are applied downstream.

### Phase 5 — CVE Mapping
Maps SBOM components to CVEs using a 3-tier lookup:

```
1. Local SQLite NVD index  →  ~5ms per lookup, 186k CVEs, 3.1M CPE rows
2. OSV batch API           →  1 HTTP call for all packages not in NVD
3. NVD REST API v2         →  per-component fallback (rate-limited)
```

Each CVE is enriched with:
- **EPSS score** — probability of exploitation in the next 30 days
- **CISA KEV** — is this CVE actively exploited in the wild?
- **CVSS v3.1** — base score + attack vector

**Example output for vulnerable test firmware:**
```
63 CVEs  |  13 CRITICAL  |  22 HIGH  |  0 KEV
Top: CVE-2024-10525 (mosquitto 9.8)  CVE-2021-42142 (tinydtls 9.8)
```

### Phase 6 — VEX Risk Analysis
Applies 7 triage rules per CVE to determine actual exploitability in **this specific firmware**:

| Rule | Condition | VEX Status |
|---|---|---|
| R1 | OS-level exploit on bare-metal AVR | `not_affected` |
| R2 | Network attack, no network hardware in HBOM | `not_affected` |
| R3 | Crypto CVE, algorithm not found in CBOM | `not_affected` |
| R4 | Hardware chip CVE (physical access required) | `under_investigation` |
| R5 | KEV + EPSS > 20% | `affected` (confidence 0.97) |
| R6 | EPSS < 0.3%, no KEV, local-only | `under_investigation` |
| R7 | Default (component present, not ruled out) | `affected` |

**Risk score formula:**
```
score = sigmoid( Σ (cvss/10 × epss_weight × kev_mult × vex_weight) / n_affected )
kev_mult = 2.0  ·  vex_weight: affected=1.0, under_inv=0.5, not_affected=0
```

Outputs: per-CVE VEX status, firmware risk score 0–100, CycloneDX 1.5 VEX document.

### Phase 7 — Compliance Report
Checks 33 controls across three standards:

| Standard | Controls | What it checks |
|---|---|---|
| **ETSI EN 303 645 v2.1.1** | 13 provisions | Default passwords, secure updates, software integrity, crypto, attack surface |
| **EU CRA 2024 Annex I** | 10 requirements | Vuln-free at launch, SBOM availability, secure defaults, update integrity |
| **OWASP IoT Top 10** | 10 controls | Hardcoded passwords, insecure update, outdated components, insecure transfer |

Each control gets: **PASS / FAIL / PARTIAL / UNKNOWN** with evidence, gap description, and remediation guidance.

**Output:** Compliance score 0–100 (Grade A–F), JSON report, and a 7-page A4 PDF with:
- Cover page (risk score gauge, device info, scan metadata)
- Executive summary (CVE stats, compliance overview)
- Full CVE table (CVSS + EPSS + VEX status)
- Control-by-control gap matrix
- CBOM crypto posture
- Prioritised remediation plan (P0 → P3)

---

## 🔌 Hardware Support

| Device | Interface | Tool | Status |
|---|---|---|---|
| Arduino UNO R3 (ATmega328P) | USB → `/dev/ttyACM0` | avrdude | ✅ Tested |
| Arduino Mega 2560 | USB → `/dev/ttyACM0` | avrdude | ✅ Supported |
| ESP32-D0WD-V3 (CP2102) | USB → `/dev/ttyUSB0` | esptool | ✅ Tested |
| ESP8266 (CH340) | USB → `/dev/ttyUSB0` | esptool | ✅ Supported |
| ESP32-S2 / S3 / C3 | USB → `/dev/ttyUSB0` | esptool | ✅ Supported |
| Linux-based IoT (OpenWrt, etc.) | Uploaded .bin/.img | binwalk/unblob | ✅ Supported |

**VMware users:** Connect the ESP32 via **VM → Removable Devices → [CP210x USB] → Connect** before running Phase 2.

---

## 🧪 Test Firmware

Two deliberately vulnerable firmware files are included for scanner validation:

### Arduino AVR (`vulnerable_firmware/vulnerable_firmware.ino`)
- **Libraries:** wolfSSL 4.0.0 · FreeRTOS 10.0.0 · lwIP 2.0.3 · Mongoose 6.14 · TinyDTLS 0.9.0 · Mosquitto 1.4.15
- **Hardware:** ATmega328P · NRF24L01 · MPU-6050 · AT24C32 · ENC28J60
- **Crypto (insecure):** MD5 · DES · RC4 · SSLv3 · TLS 1.0 · XOR
- **Issues:** Hardcoded WiFi/MQTT/AWS creds · HTTP OTA unsigned · Secure boot DISABLED · Debug UART backdoor

### ESP32 (`vulnerable_firmware_esp32/vulnerable_firmware_esp32/vulnerable_firmware_esp32.ino`)
- **SDK:** ESP-IDF 4.4.1 · mbedTLS 2.16.0 · lwIP 2.1.2 · FreeRTOS 10.4.3
- **Libraries:** PubSubClient 2.7 · ArduinoJson 5.13.3 · WiFiManager 0.16.0
- **Hardware:** ESP32-D0WD-V3 · GD25Q32 4MB Flash · BME280 · DS3231
- **Issues:** Real telnet backdoor on port 23 · Unsigned HTTP OTA · MySQL connection string in flash · All CBOM weak/insecure

**Flash the test firmware:**
```bash
# Arduino
arduino-cli compile --fqbn arduino:avr:uno vulnerable_firmware
arduino-cli upload  --fqbn arduino:avr:uno --port /dev/ttyACM0 vulnerable_firmware

# ESP32 (requires arduino-cli ESP32 core)
arduino-cli compile --fqbn esp32:esp32:esp32 vulnerable_firmware_esp32/vulnerable_firmware_esp32
arduino-cli upload  --fqbn esp32:esp32:esp32 --port /dev/ttyUSB0 vulnerable_firmware_esp32/vulnerable_firmware_esp32
```

---

## 📁 Project Structure

```
IIFVDCAS/
├── backend/
│   ├── main.py                          # FastAPI app, all 7 phase routers
│   ├── requirements.txt
│   └── core/
│       ├── device_detection/            # Phase 1 — USB/serial/network scan
│       ├── firmware_extraction/         # Phase 2 — esptool + avrdude + binwalk
│       ├── static_analysis/             # Phase 3 — S12·S13·S45·S108 + AVR
│       ├── sbom/                        # Phase 4 — SBOM + HBOM + CBOM
│       │   └── avr_component_extractor.py  # String-scan → CPE mapping
│       ├── cve_mapping/                 # Phase 5 — NVD SQLite + OSV + EPSS
│       │   ├── build_nvd_index.py       # One-time NVD → SQLite indexer
│       │   └── nvd_lookup.py            # 5ms lookup, mmap, thread-local conn
│       ├── vex_engine/                  # Phase 6 — VEX triage + risk score
│       │   ├── triage_engine.py         # 7 rules, architecture-aware
│       │   ├── risk_scorer.py           # CVSS × EPSS × KEV formula
│       │   └── vex_document.py          # CycloneDX 1.5 VEX output
│       ├── compliance/                  # Phase 7 — gap check + PDF
│       │   ├── gap_checker.py           # 33 controls: ETSI/CRA/OWASP
│       │   ├── pdf_builder.py           # ReportLab A4, canvas cover page
│       │   └── report_generator.py      # Orchestrator
│       └── ai/                          # AI integration (optional)
│           ├── routes.py
│           └── providers.py
├── frontend/
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx
│       │   ├── DeviceDetection.jsx      # Phase 1 UI
│       │   ├── FirmwareExtraction.jsx   # Phase 2 UI (esptool + avrdude)
│       │   ├── StaticAnalysis.jsx       # Phase 3 UI
│       │   ├── SBOM.jsx                 # Phase 4 UI
│       │   ├── CvePage.jsx              # Phase 5 UI
│       │   ├── VEXPage.jsx              # Phase 6 UI
│       │   └── CompliancePage.jsx       # Phase 7 UI + PDF download
│       ├── utils/api.js                 # All 7 phase API clients
│       └── hooks/useWebSocket.js        # Live progress streaming
├── vulnerable_firmware/                 # AVR test firmware (intentionally insecure)
├── vulnerable_firmware_esp32/           # ESP32 test firmware (intentionally insecure)
└── scripts/
    ├── dev.sh                           # Start backend + frontend
    └── install.sh                       # Dependency installer
```

---

## 📊 Validated Results (Vulnerable Test Firmware — AVR)

Running the full 7-phase pipeline against the included Arduino test firmware:

| Phase | Result |
|---|---|
| **P1 Device** | ATmega328P on `/dev/ttyACM0` |
| **P2 Extraction** | 32 KB flash read via avrdude |
| **P3 Static** | Risk 64/100 HIGH · 18 credentials · 8 backdoor strings |
| **P4 SBOM** | 18 SW components · 5 HW components · 7 crypto assets |
| **P4 CBOM** | DES (insecure) · MD5 (weak) · RC4 (insecure) · SSLv3 (insecure) |
| **P5 CVE** | 63 CVEs · 13 CRITICAL · 22 HIGH · 0 KEV |
| **P5 Top CVE** | CVE-2024-10525 mosquitto CVSS 9.8 · CVE-2021-42142 tinydtls CVSS 9.8 |
| **P6 VEX** | Risk 83/100 HIGH · 55 affected · 4 not_affected (OS exploits dismissed on AVR) |
| **P7 Compliance** | Grade F · 16.4/100 · 15 FAIL controls |
| **P7 PDF** | 17 KB, 7 pages, downloadable |

---

## 🗺 Project Status

### ✅ Completed

- [x] **Phase 1** — Device detection (USB/serial/network, 17 fingerprints)
- [x] **Phase 2** — Firmware extraction (ESP32 esptool with 4-attempt retry ladder, AVR avrdude, binwalk/unblob pipeline)
- [x] **Phase 3** — Static analysis (S12, S13, S20, S45, S60, S85, S107, S108, AVR disassembly)
- [x] **Phase 4** — SBOM/HBOM/CBOM (CycloneDX 1.5, string-scan library detection, 25+ library signatures)
- [x] **Phase 5** — CVE mapping (291 MB NVD SQLite index, OSV batch API, EPSS, CISA KEV)
- [x] **Phase 6** — VEX risk analysis (7 triage rules, architecture-aware, risk score formula, CycloneDX VEX)
- [x] **Phase 7** — Compliance report (33 controls, ETSI/CRA/OWASP, ReportLab PDF, JSON export)
- [x] **Frontend** — Full React UI for all 7 phases, WebSocket live progress
- [x] **ESP32 toolchain fix** — `read_flash` syntax, 4-attempt baud ladder, `--no-stub` ROM fallback
- [x] **Architecture detection** — ESP32 correctly identified before AVR fallback (fixes VEX triage)
- [x] **NVD SQLite** — 186k CVEs, 3.1M CPE rows, thread-local mmap connections (5ms lookup)
- [x] **Test firmware** — Arduino + ESP32 vulnerable firmware for scanner validation

### 🔄 In Progress

- [ ] **ESP32 Arduino core install** — `arduino-cli core install esp32:esp32` (318 MB download, VM network instability causes timeouts — resumes from cache)
- [ ] **ESP32 full pipeline test** — Flash vulnerable firmware and run P1→P7 end-to-end
- [ ] **generator.py ESP32 fix** — Architecture detection patch for SBOM (written, needs git push verification)

### 📋 Pending / Planned

- [ ] **AI integration (Phase 5)** — CVE impact analyst: explains what each CVE means in your specific firmware context
- [ ] **AI integration (Phase 6)** — VEX justification generator: writes CycloneDX-compliant justification text automatically
- [ ] **AI integration (Phase 7)** — Compliance formal write-up: non-conformance paragraphs for audit submissions
- [ ] **ESP32 partition-aware extraction** — Read individual partitions (bootloader, app0, nvs, spiffs) instead of full flash dump
- [ ] **IEC 62443-4-2 compliance** — Component security level checks (Phase 7 extension)
- [ ] **Docker deployment** — `docker-compose.yml` for customer self-hosted deployment
- [ ] **Scan history / diff** — Compare two scans, show what changed
- [ ] **GitHub Actions CI** — Automated tests for all 7 phases
- [ ] **Dynamic analysis (Phase dynamic)** — QEMU-based firmware emulation and runtime analysis

---

## 🛠 Dependencies

```
# Core backend
fastapi==0.104.1
uvicorn==0.24.0
python-multipart==0.0.6
aiofiles==23.2.1
requests==2.31.0
reportlab==4.5.1
anthropic==0.28.0

# Analysis tools (system)
binwalk       → filesystem extraction
checksec      → ELF binary security properties
avrdude       → AVR flash read/write
esptool       → ESP32/ESP8266 flash read/write
avr-binutils  → avr-objdump disassembly
bandit        → Python static analysis
shellcheck    → Shell script analysis
strings       → embedded string extraction
```

---

## 👨‍💻 Author

**Naji** — Final Year BS Cybersecurity, UMT Lahore  
GitHub: [@sudoNaji](https://github.com/sudoNaji)

Holds the **Google Cybersecurity Professional Certificate** (all 9 courses). Targeting Junior DevSecOps Engineer and SOC Tier 1 roles. This project demonstrates full-stack security platform development, IoT firmware analysis, CVE/vulnerability management, and standards-based compliance reporting.

---

## ⚠ Disclaimer

The vulnerable test firmware files in this repository are **intentionally insecure** and provided **solely for testing the IIFVDCAS scanner**. They should never be deployed in a production environment. All security testing was performed on hardware owned by the author in a controlled lab environment.

---

<div align="center">

**IIFVDCAS** — Built with 🛡️ for IoT Security Research

[![GitHub](https://img.shields.io/badge/GitHub-sudoNaji-181717?style=flat-square&logo=github)](https://github.com/sudoNaji)

</div>
