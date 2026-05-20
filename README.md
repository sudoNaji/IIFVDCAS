# IIFVDCAS
## Intelligent IoT Firmware Vulnerability Detection & Compliance Assessment System

[![Phase](https://img.shields.io/badge/Phase-1%20Device%20Detection-brightgreen)]()
[![License](https://img.shields.io/badge/License-GPLv3-blue)]()
[![Python](https://img.shields.io/badge/Python-3.11+-yellow)]()
[![React](https://img.shields.io/badge/React-18-61DAFB)]()

> GUI-based firmware security platform powered by EMBA's analysis engine — built for the web, packaged for Windows & Linux.

## Quick Start
```bash
git clone https://github.com/YOUR_USERNAME/IIFVDCAS.git && cd IIFVDCAS
./scripts/install.sh    # Install all dependencies
./scripts/dev.sh        # Start frontend + backend
# Open: http://localhost:5173
```

## Phase Roadmap
| Phase | Feature | Status |
|---|---|---|
| 1 | IoT Device Detection | ✅ Complete |
| 2 | Firmware Extraction | 🔜 Next |
| 3 | Static Analysis | ⏳ Planned |
| 4 | SBOM / HBOM / CBOM | ⏳ Planned |
| 5 | CVE Mapping | ⏳ Planned |
| 6 | VEX Risk Analysis | ⏳ Planned |
| 7 | Compliance Reporting | ⏳ Planned |
| 8 | Dynamic Analysis | ⏳ Planned |
| 9 | Desktop Release (Win/Linux) | ⏳ Planned |

## Tech Stack
- **Frontend**: React 18 + Vite + Tailwind CSS
- **Backend**: Python 3.11 + FastAPI + WebSockets
- **Engine**: EMBA v2.0.1 (shell module bridge)
- **Tools**: binwalk · checksec · nmap · john · qemu · CycloneDX

**UMT Lahore FYP 2025–2026**
