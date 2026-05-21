"""
IIFVDCAS — Phase 1: IoT Device Detection Engine
Mirrors EMBA logic: P02_firmware_bin_file_check, S06_distribution_identification,
udevadm info, lsusb, pyserial port enumeration.
"""
import subprocess, re, hashlib
import serial.tools.list_ports
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

@dataclass
class IoTDevice:
    id: str
    detected_at: str
    connection_type: str
    port: Optional[str] = None
    vendor_id: Optional[str] = None
    product_id: Optional[str] = None
    vendor_name: Optional[str] = None
    product_name: Optional[str] = None
    serial_number: Optional[str] = None
    device_class: Optional[str] = None
    chipset: Optional[str] = None
    architecture: Optional[str] = None
    firmware_version: Optional[str] = None
    baud_rate: int = 115200
    driver: Optional[str] = None
    raw_info: dict = field(default_factory=dict)
    status: str = "detected"

@dataclass
class DeviceScanResult:
    scan_id: str
    scanned_at: str
    devices: list = field(default_factory=list)
    total_found: int = 0
    scan_duration_ms: int = 0

KNOWN_DEVICES = {
    ("2341","0043"): ("Arduino Uno R3",             "ATmega328P",  "AVR"),
    ("2341","0001"): ("Arduino Uno",                 "ATmega328P",  "AVR"),
    ("2341","0010"): ("Arduino Mega 2560",           "ATmega2560",  "AVR"),
    ("2341","0042"): ("Arduino Mega 2560 R3",        "ATmega2560",  "AVR"),
    ("2341","8036"): ("Arduino Leonardo",            "ATmega32U4",  "AVR"),
    ("2341","804d"): ("Arduino Due",                 "AT91SAM3X8E", "ARM Cortex-M3"),
    ("2341","8057"): ("Arduino Nano 33 BLE",         "nRF52840",    "ARM Cortex-M4"),
    ("2341","8054"): ("Arduino Nano 33 IoT",         "SAMD21G18A",  "ARM Cortex-M0+"),
    ("1a86","7523"): ("CH340 Serial Clone",          "CH340G",      "N/A"),
    ("10c4","ea60"): ("CP2102 Serial (ESP32/ESP8266)","CP2102",     "Xtensa LX6"),
    ("0403","6001"): ("FTDI Serial",                 "FT232RL",     "N/A"),
    ("0403","6015"): ("FTDI Serial",                 "FT231X",      "N/A"),
    ("239a","800b"): ("Adafruit Feather M0",         "SAMD21G18A",  "ARM Cortex-M0+"),
    ("303a","0002"): ("ESP32-S2",                    "ESP32-S2",    "Xtensa LX7"),
    ("303a","1001"): ("ESP32-S3",                    "ESP32-S3",    "Xtensa LX7"),
    ("2e8a","0005"): ("Raspberry Pi Pico",           "RP2040",      "ARM Cortex-M0+"),
    ("2e8a","000a"): ("Raspberry Pi Pico W",         "RP2040",      "ARM Cortex-M0+"),
}

ARCH_PATTERNS = [
    (r"ATmega|ATtiny|AVR",                     "AVR"),
    (r"ESP32|ESP8266|Xtensa",                   "Xtensa"),
    (r"Cortex-M0|Cortex-M3|Cortex-M4|SAM|nRF", "ARM"),
    (r"BCM28",                                  "ARM (Broadcom)"),
    (r"RP2040",                                 "ARM Cortex-M0+"),
    (r"MIPS",                                   "MIPS"),
]

def _run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return "", str(e)

def _make_id(port="", vid="", pid=""):
    raw = f"{port}-{vid}-{pid}-{datetime.now(timezone.utc).isoformat()}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]

def _detect_arch_from_chipset(chipset):
    for pattern, arch in ARCH_PATTERNS:
        if re.search(pattern, chipset, re.IGNORECASE):
            return arch
    return None

def _guess_device_from_vendor(vendor):
    v = vendor.lower()
    if any(k in v for k in ["arduino","microchip"]): return "Arduino / Microcontroller"
    if any(k in v for k in ["espressif","esp"]):      return "ESP32 / ESP8266"
    if any(k in v for k in ["raspberry","broadcom"]): return "Raspberry Pi"
    if any(k in v for k in ["tp-link","d-link","netgear","asus","linksys"]): return "Network Router / AP"
    return "Unknown Network Device"

def _is_real_iot_device(port):
    """
    Filter out VMware/virtual/native COM ports that have no real USB device.
    A real IoT device MUST have a USB VID:PID or udevadm ID_VENDOR.
    ttyS* (standard UART) without VID are virtual/motherboard UARTs — skip them.
    ttyACM*, ttyUSB* are real USB CDC/serial devices — always keep.
    """
    import os
    if port.device and re.match(r'/dev/ttyS\d+', port.device):
        # For ttyS* ports: only keep if it has a real USB VID
        if not port.vid:
            return False
    return True

def scan_usb_serial_devices():
    """
    Detect USB-connected IoT devices.
    Filters out VMware virtual ttyS* ports with no USB VID.
    Mirrors EMBA's udevadm-based device identification.
    """
    devices = []
    for port in serial.tools.list_ports.comports():
        # Skip virtual/motherboard UARTs
        if not _is_real_iot_device(port):
            continue

        vid_hex = f"{port.vid:04x}" if port.vid else None
        pid_hex = f"{port.pid:04x}" if port.pid else None

        device_class, chipset, arch = None, None, None
        if vid_hex and pid_hex:
            key = (vid_hex, pid_hex)
            if key in KNOWN_DEVICES:
                device_class, chipset, arch = KNOWN_DEVICES[key]

        # Enrich with udevadm (mirrors EMBA's udevadm info call)
        raw_udev = {}
        if port.device:
            udev_out, _ = _run(["udevadm","info",f"--name={port.device}","--query=all"])
            for line in udev_out.splitlines():
                if line.startswith("E: "):
                    k, _, v = line[3:].partition("=")
                    raw_udev[k] = v

        if not device_class:
            device_class = (raw_udev.get("ID_MODEL_FROM_DATABASE")
                           or raw_udev.get("ID_MODEL")
                           or port.description)
        vendor_name = (raw_udev.get("ID_VENDOR_FROM_DATABASE")
                      or raw_udev.get("ID_VENDOR")
                      or port.manufacturer)
        if chipset and not arch:
            arch = _detect_arch_from_chipset(chipset)

        devices.append(IoTDevice(
            id=_make_id(port.device or "", vid_hex or "", pid_hex or ""),
            detected_at=datetime.now(timezone.utc).isoformat(),
            connection_type="usb",
            port=port.device,
            vendor_id=vid_hex,
            product_id=pid_hex,
            vendor_name=vendor_name,
            product_name=raw_udev.get("ID_MODEL") or port.product,
            serial_number=raw_udev.get("ID_SERIAL_SHORT") or port.serial_number,
            device_class=device_class or "Unknown IoT Device",
            chipset=chipset,
            architecture=arch,
            driver=raw_udev.get("DRIVER"),
            raw_info=raw_udev,
        ))
    return devices

def scan_network_devices(subnet=None):
    devices = []
    if not subnet:
        ip_out, _ = _run(["hostname","-I"])
        ips = ip_out.split()
        if ips:
            parts = ips[0].rsplit(".",1)
            subnet = f"{parts[0]}.0/24"
        else:
            return devices
    nmap_out, _ = _run(["nmap","-sn","--open","-T4",subnet], timeout=60)
    current_ip = None
    for line in nmap_out.splitlines():
        ip_m = re.search(r"Nmap scan report for (.+)", line)
        if ip_m: current_ip = ip_m.group(1).strip()
        mac_m = re.search(r"MAC Address: ([0-9A-F:]{17})\s*\((.+)\)", line)
        if mac_m and current_ip:
            mac, vendor = mac_m.group(1), mac_m.group(2)
            devices.append(IoTDevice(
                id=_make_id(current_ip, mac),
                detected_at=datetime.now(timezone.utc).isoformat(),
                connection_type="network",
                vendor_name=vendor,
                device_class=_guess_device_from_vendor(vendor),
                raw_info={"ip": current_ip, "mac": mac, "vendor": vendor},
            ))
    return devices

def probe_device_firmware_info(device):
    if device.connection_type != "usb" or not device.port:
        return device
    try:
        import serial, time
        with serial.Serial(device.port, device.baud_rate, timeout=2) as ser:
            time.sleep(2)
            for probe in [b"AT+GMR\r\n", b"VERSION\r\n", b"\r\n"]:
                ser.reset_input_buffer()
                ser.write(probe)
                time.sleep(0.5)
                if ser.in_waiting > 0:
                    raw = ser.read(ser.in_waiting).decode("utf-8", errors="replace").strip()
                    if raw:
                        device.raw_info.setdefault("probe_responses", []).append(raw)
                        ver_m = re.search(r"v(\d+\.\d+[\.\d]*)", raw)
                        if ver_m and not device.firmware_version:
                            device.firmware_version = ver_m.group(1)
    except Exception as e:
        logger.debug(f"Probe failed: {e}")
    return device

def run_full_device_scan(include_network=False, subnet=None):
    import time, hashlib
    start = time.time()
    scan_id = hashlib.md5(str(start).encode()).hexdigest()[:8]
    all_devices = scan_usb_serial_devices()
    all_devices = [probe_device_firmware_info(d) for d in all_devices]
    if include_network:
        all_devices.extend(scan_network_devices(subnet))
    return DeviceScanResult(
        scan_id=scan_id,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        devices=all_devices,
        total_found=len(all_devices),
        scan_duration_ms=int((time.time()-start)*1000),
    )

def get_device_details(port):
    info = {}
    out, _ = _run(["udevadm","info",f"--name={port}","--query=all"])
    for line in out.splitlines():
        if line.startswith("E: "):
            k, _, v = line[3:].partition("=")
            info[k] = v
    stat_out, _ = _run(["stat", port])
    info["stat"] = stat_out
    stty_out, _ = _run(["stty","-F",port,"-a"])
    info["stty"] = stty_out
    return info
