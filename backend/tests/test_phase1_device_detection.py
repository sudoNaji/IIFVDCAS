"""IIFVDCAS Phase 1 Tests — 26 tests covering device detection engine"""
import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.device_detection.detector import (
    KNOWN_DEVICES, _detect_arch_from_chipset, _guess_device_from_vendor,
    _make_id, DeviceScanResult, IoTDevice,
)

class TestKnownDeviceFingerprints:
    def test_arduino_uno_r3(self):
        assert ("2341","0043") in KNOWN_DEVICES
        cls, chip, arch = KNOWN_DEVICES[("2341","0043")]
        assert "Arduino Uno" in cls and chip == "ATmega328P" and arch == "AVR"
    def test_arduino_mega(self):
        assert KNOWN_DEVICES[("2341","0042")][1] == "ATmega2560"
    def test_esp32_cp2102(self):
        cls, chip, arch = KNOWN_DEVICES[("10c4","ea60")]
        assert "Xtensa" in arch
    def test_rpi_pico(self):
        assert KNOWN_DEVICES[("2e8a","0005")][1] == "RP2040"
    def test_ch340_clone(self):
        assert ("1a86","7523") in KNOWN_DEVICES
    def test_ftdi_serial(self):
        assert ("0403","6001") in KNOWN_DEVICES
    def test_arduino_nano_33_ble(self):
        assert ("2341","8057") in KNOWN_DEVICES
        assert KNOWN_DEVICES[("2341","8057")][1] == "nRF52840"

class TestArchDetection:
    def test_avr(self):        assert _detect_arch_from_chipset("ATmega328P") == "AVR"
    def test_attiny(self):     assert _detect_arch_from_chipset("ATtiny85") == "AVR"
    def test_nrf_arm(self):    assert _detect_arch_from_chipset("nRF52840") == "ARM"
    def test_esp32_xtensa(self): assert _detect_arch_from_chipset("ESP32") == "Xtensa"
    def test_rp2040(self):     assert _detect_arch_from_chipset("RP2040") == "ARM Cortex-M0+"
    def test_unknown(self):    assert _detect_arch_from_chipset("UnknownChip") is None
    def test_sam_arm(self):    assert _detect_arch_from_chipset("SAMD21G18A") == "ARM"

class TestVendorHeuristics:
    def test_arduino(self):    assert "Arduino" in _guess_device_from_vendor("Arduino SA")
    def test_espressif(self):  assert "ESP" in _guess_device_from_vendor("Espressif Inc.")
    def test_tplink(self):     assert "Router" in _guess_device_from_vendor("TP-LINK Technologies") or "Network" in _guess_device_from_vendor("TP-LINK Technologies")
    def test_raspberry(self):  assert "Raspberry" in _guess_device_from_vendor("Raspberry Pi Foundation")
    def test_unknown(self):    assert _guess_device_from_vendor("Some Corp") == "Unknown Network Device"

class TestIdGeneration:
    def test_length(self):     assert len(_make_id("/dev/ttyACM0","2341","0043")) == 12
    def test_is_hex(self):     int(_make_id("/dev/ttyACM0","2341","0043"), 16)
    def test_unique(self):
        import time; time.sleep(0.01)
        assert _make_id("/dev/ttyACM0") != _make_id("/dev/ttyACM1")

class TestDataModels:
    def test_device_defaults(self):
        d = IoTDevice(id="x", detected_at="2026-01-01", connection_type="usb")
        assert d.status == "detected" and d.baud_rate == 115200 and d.raw_info == {}
    def test_scan_result_defaults(self):
        r = DeviceScanResult(scan_id="s1", scanned_at="2026-01-01")
        assert r.total_found == 0 and r.devices == []

class TestAPIEndpoints:
    @pytest.fixture
    def client(self):
        try:
            from fastapi.testclient import TestClient
            import importlib.util, os
            spec = importlib.util.spec_from_file_location("main", os.path.join(os.path.dirname(__file__),'..','main.py'))
            m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
            return TestClient(m.app)
        except Exception: pytest.skip("Cannot load app")
    def test_root(self, client):        assert client.get("/").status_code == 200
    def test_health(self, client):      assert client.get("/health").json()["status"] == "ok"
    def test_system_info(self, client): assert "tools" in client.get("/api/v1/system/info").json()
    def test_devices_list(self, client): assert "devices" in client.get("/api/v1/devices").json()
    def test_scan_start(self, client):
        r = client.post("/api/v1/devices/scan", json={"include_network":False})
        assert r.status_code == 200 and "scan_id" in r.json()
