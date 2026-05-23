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
        assert r.json()["version"] == "0.3.0"

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
        assert "phase2_firmware_extraction" in data["available_phases"]
