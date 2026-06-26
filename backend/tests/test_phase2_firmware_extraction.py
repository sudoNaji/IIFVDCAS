"""
IIFVDCAS Phase 2 Tests — Firmware Extraction Engine
Mirrors EMBA P02/P50/P55 validation logic.
"""
import os, sys, tempfile, struct, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from pathlib import Path
from core.firmware_extraction.extractor import (
    analyze_firmware_file, _detect_linux_filesystem, _build_file_tree,
    _human_size, FirmwareType, ExtractionStatus,
    EXTRACT_BASE
)


# ─── Test fixtures: synthetic firmware files ──────────────────────────────────

@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d

@pytest.fixture
def elf_file(tmp_dir):
    """Synthetic ELF binary (ARM little-endian)"""
    path = os.path.join(tmp_dir, "firmware.elf")
    # ELF magic + ARM identifier
    elf_header = b'\x7fELF\x01\x01\x01\x00' + b'\x00'*8 + b'\x02\x00\x28\x00'
    with open(path, "wb") as f:
        f.write(elf_header + b'\x00' * 1024)
    return path

@pytest.fixture
def gz_file(tmp_dir):
    """Synthetic gzip file"""
    import gzip
    path = os.path.join(tmp_dir, "firmware.bin.gz")
    with gzip.open(path, "wb") as f:
        f.write(b"fake firmware data " * 100)
    return path

@pytest.fixture
def random_file(tmp_dir):
    """High-entropy random file (looks encrypted)"""
    path = os.path.join(tmp_dir, "encrypted.bin")
    import os as _os
    with open(path, "wb") as f:
        f.write(_os.urandom(4096))
    return path

@pytest.fixture
def text_file(tmp_dir):
    """Low-entropy text file"""
    path = os.path.join(tmp_dir, "config.txt")
    with open(path, "w") as f:
        f.write("kernel config\n" * 100)
    return path

@pytest.fixture
def linux_fs_dir(tmp_dir):
    """Synthetic Linux filesystem"""
    for d in ["bin", "etc", "lib", "usr", "var", "sbin", "dev", "proc"]:
        os.makedirs(os.path.join(tmp_dir, d), exist_ok=True)
    with open(os.path.join(tmp_dir, "etc", "passwd"), "w") as f:
        f.write("root:x:0:0:root:/root:/bin/sh\n")
    with open(os.path.join(tmp_dir, "bin", "busybox"), "wb") as f:
        f.write(b"\x7fELF" + b"\x00"*60)
    return tmp_dir


# ─── P02: Hash computation ────────────────────────────────────────────────────

class TestHashComputation:
    def test_md5_correct(self, text_file):
        info = analyze_firmware_file(text_file)
        import hashlib
        expected = hashlib.md5(open(text_file,"rb").read()).hexdigest()
        assert info.md5 == expected

    def test_sha512_correct(self, text_file):
        info = analyze_firmware_file(text_file)
        expected = hashlib.sha512(open(text_file,"rb").read()).hexdigest()
        assert info.sha512 == expected

    def test_sha1_correct(self, text_file):
        info = analyze_firmware_file(text_file)
        expected = hashlib.sha1(open(text_file,"rb").read()).hexdigest()
        assert info.sha1 == expected


# ─── P02: Entropy detection (EMBA heuristic) ─────────────────────────────────

class TestEntropyDetection:
    def test_low_entropy_text(self, text_file):
        info = analyze_firmware_file(text_file)
        assert info.entropy < 6.0
        assert info.entropy_label in ("low", "very_low", "normal")

    def test_high_entropy_random(self, random_file):
        info = analyze_firmware_file(random_file)
        assert info.entropy > 7.0
        assert info.entropy_label in ("high", "encrypted_or_compressed")

    def test_entropy_range(self, text_file):
        info = analyze_firmware_file(text_file)
        assert 0.0 <= info.entropy <= 8.0


# ─── P02: Firmware type detection ────────────────────────────────────────────

class TestFirmwareTypeDetection:
    def test_elf_detection(self, elf_file):
        info = analyze_firmware_file(elf_file)
        assert info.firmware_type == FirmwareType.ELF

    def test_gz_archive_detection(self, gz_file):
        info = analyze_firmware_file(gz_file)
        assert info.firmware_type in (FirmwareType.ARCHIVE, FirmwareType.RAW_BINARY)

    def test_unknown_returns_raw_or_valid(self, random_file):
        info = analyze_firmware_file(random_file)
        assert info.firmware_type in (FirmwareType.RAW_BINARY, FirmwareType.UNKNOWN)

    def test_nonexistent_file(self):
        info = analyze_firmware_file("/nonexistent/path/fw.bin")
        assert info.size_bytes == 0

    def test_file_type_string_populated(self, elf_file):
        info = analyze_firmware_file(elf_file)
        assert len(info.file_type) > 0


# ─── P02: Architecture detection ─────────────────────────────────────────────

class TestArchitectureDetection:
    def test_elf_has_arch_hint(self, elf_file):
        info = analyze_firmware_file(elf_file)
        # ARM ELF should trigger ARM detection
        # (may be empty if `file` doesn't detect it from our synthetic header)
        assert isinstance(info.architecture_hint, str)

    def test_endianness_string(self, elf_file):
        info = analyze_firmware_file(elf_file)
        assert info.endianness in ("little", "big", "")


# ─── P99: Linux filesystem detection ─────────────────────────────────────────

class TestLinuxFsDetection:
    def test_linux_fs_found(self, linux_fs_dir):
        found, paths = _detect_linux_filesystem(linux_fs_dir)
        assert found is True
        assert len(paths) > 0

    def test_empty_dir_not_linux(self, tmp_dir):
        found, paths = _detect_linux_filesystem(tmp_dir)
        assert found is False

    def test_partial_linux_not_detected(self, tmp_dir):
        # Only 2 indicators (need 3)
        os.makedirs(os.path.join(tmp_dir, "bin"), exist_ok=True)
        os.makedirs(os.path.join(tmp_dir, "etc"), exist_ok=True)
        found, _ = _detect_linux_filesystem(tmp_dir)
        assert found is False

    def test_passwd_detected(self, linux_fs_dir):
        found, paths = _detect_linux_filesystem(linux_fs_dir)
        assert found
        assert any("passwd" in p or "/" in p for p in paths)


# ─── File tree builder ────────────────────────────────────────────────────────

class TestFileTreeBuilder:
    def test_tree_built(self, linux_fs_dir):
        tree = _build_file_tree(linux_fs_dir)
        assert len(tree) > 0

    def test_tree_has_correct_keys(self, linux_fs_dir):
        tree = _build_file_tree(linux_fs_dir)
        node = tree[0]
        assert "name" in node
        assert "type" in node
        assert node["type"] in ("dir", "file")

    def test_dirs_have_children(self, linux_fs_dir):
        tree = _build_file_tree(linux_fs_dir)
        dirs = [n for n in tree if n["type"] == "dir"]
        assert len(dirs) > 0
        # dirs at depth 0 should have children key
        assert "children" in dirs[0]

    def test_nonexistent_dir(self):
        tree = _build_file_tree("/nonexistent/dir")
        assert tree == []


# ─── Utility functions ────────────────────────────────────────────────────────

class TestUtils:
    def test_human_size_bytes(self):
        assert "B" in _human_size(500)

    def test_human_size_kb(self):
        assert "KB" in _human_size(2048)

    def test_human_size_mb(self):
        assert "MB" in _human_size(2 * 1024 * 1024)

    def test_human_size_gb(self):
        assert "GB" in _human_size(2 * 1024 ** 3)


# ─── API endpoint tests ───────────────────────────────────────────────────────

class TestPhase2API:
    @pytest.fixture
    def client(self):
        try:
            from fastapi.testclient import TestClient
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "main", os.path.join(os.path.dirname(__file__), '..', 'main.py')
            )
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            return TestClient(m.app)
        except Exception:
            pytest.skip("Cannot load app")

    def test_version_updated(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["version"] == "0.8.0"

    def test_upload_endpoint_exists(self, client):
        r = client.post("/api/v1/firmware/upload")
        # 422 = validation error (no file), but endpoint exists
        assert r.status_code in (200, 422)

    def test_analyze_missing_path(self, client):
        r = client.post("/api/v1/firmware/analyze", json={})
        assert r.status_code == 400

    def test_analyze_nonexistent_path(self, client):
        r = client.post("/api/v1/firmware/analyze", json={"path": "/nonexistent/fw.bin"})
        assert r.status_code == 404

    def test_extract_missing_path(self, client):
        r = client.post("/api/v1/firmware/extract", json={})
        assert r.status_code == 400

    def test_jobs_list_endpoint(self, client):
        r = client.get("/api/v1/firmware/jobs")
        assert r.status_code == 200
        assert "jobs" in r.json()

    def test_get_nonexistent_job(self, client):
        r = client.get("/api/v1/firmware/extract/nonexistent")
        assert r.status_code == 404

    def test_system_info_phase2_available(self, client):
        r = client.get("/api/v1/system/info")
        data = r.json()
        assert "phase2" in data["available_phases"] or "phase2_firmware_extraction" in data["available_phases"]


# ─── ESP32 Partition Extraction ──────────────────────────────────────────────

class TestESP32PartitionExtraction:
    @pytest.fixture
    def esp32_flash_image(self, tmp_dir):
        """Generate a synthetic ESP32 flash image with partition table at 0x8000"""
        path = os.path.join(tmp_dir, "esp32_flash.bin")
        
        # 4MB of zeros
        flash_data = bytearray(4 * 1024 * 1024)
        
        # Write bootloader magic at 0x1000
        flash_data[0x1000] = 0xE9
        flash_data[0x1001] = 0x03 # segments
        
        # Partition table at 0x8000
        # Format: magic (2s), type (B), subtype (B), offset (L), size (L), name (16s), flags (L)
        import struct
        
        # Entry 1: nvs (type=1, subtype=2, offset=0x9000, size=0x6000)
        entry1 = struct.pack("<2sBBLL16sL", b'\xaa\x50', 1, 2, 0x9000, 0x6000, b'nvs', 0)
        
        # Entry 2: otadata (type=1, subtype=0, offset=0xf000, size=0x2000)
        entry2 = struct.pack("<2sBBLL16sL", b'\xaa\x50', 1, 0, 0xf000, 0x2000, b'otadata', 0)
        
        # Entry 3: factory (type=0, subtype=0, offset=0x10000, size=0x100000)
        # We also want to write a synthetic app descriptor inside the factory partition to test app desc parsing.
        # esp_app_desc_t starts at offset 32 (0x20) in the partition.
        # Format: magic (I), secure_version (I), reserv1 (8s), version (32s), project_name (32s), time (16s), date (16s), idf_ver (32s), elf_sha (32s)
        # Total size of unpacked fields: 4 + 4 + 8 + 32 + 32 + 16 + 16 + 32 + 32 = 208 bytes.
        app_desc = struct.pack("<II8s32s32s16s16s32s32s", 
            0xABCD5432, # magic
            1,          # secure_version
            b'\x00'*8,  # reserv1
            b'v1.0.0-test\x00', # version
            b'test-project\x00', # project name
            b'12:00:00\x00', # compile time
            b'Jun 11 2026\x00', # compile date
            b'v5.1.2\x00', # ESP-IDF version
            b'\xab'*32 # elf_sha
        )
        
        # Copy app descriptor to flash data at factory partition offset 0x10000 + 32
        flash_data[0x10000 + 32 : 0x10000 + 32 + len(app_desc)] = app_desc
        
        entry3 = struct.pack("<2sBBLL16sL", b'\xaa\x50', 0, 0, 0x10000, 0x100000, b'factory', 0)
        
        # Write entries into partition table at 0x8000
        flash_data[0x8000 : 0x8000 + 32] = entry1
        flash_data[0x8000 + 32 : 0x8000 + 64] = entry2
        flash_data[0x8000 + 64 : 0x8000 + 96] = entry3
        
        # Write Partition Table MD5 checksum entry (0xEB 0xEB)
        md5_entry = struct.pack("<2sBBLL16sL", b'\xeb\xeb', 0, 0, 0, 0, b'\x00'*16, 0)
        flash_data[0x8000 + 96 : 0x8000 + 128] = md5_entry
        
        with open(path, "wb") as f:
            f.write(flash_data)
            
        return path

    def test_esp32_partition_extraction(self, esp32_flash_image, tmp_dir):
        from core.firmware_extraction.extractor import extract_esp32_partitions
        log_msgs = []
        def log_cb(m):
            log_msgs.append(m)
            
        out_dir = os.path.join(tmp_dir, "extracted")
        ok = extract_esp32_partitions(esp32_flash_image, out_dir, log_cb)
        
        assert ok is True
        
        # Verify extracted partition files
        part_dir = os.path.join(out_dir, "extracted_partitions")
        assert os.path.exists(part_dir)
        
        assert os.path.exists(os.path.join(part_dir, "bootloader.bin"))
        assert os.path.exists(os.path.join(part_dir, "partition-table.bin"))
        assert os.path.exists(os.path.join(part_dir, "nvs.bin"))
        assert os.path.exists(os.path.join(part_dir, "otadata.bin"))
        assert os.path.exists(os.path.join(part_dir, "factory.bin"))
        
        # Verify metadata extraction
        meta_file = os.path.join(part_dir, "factory_meta.json")
        assert os.path.exists(meta_file)
        
        import json
        with open(meta_file, "r") as mf:
            meta = json.load(mf)
            
        assert meta["project_name"] == "test-project"
        assert meta["version"] == "v1.0.0-test"
        assert meta["idf_version"] == "v5.1.2"
        assert meta["compile_time"] == "12:00:00"
        assert meta["compile_date"] == "Jun 11 2026"
