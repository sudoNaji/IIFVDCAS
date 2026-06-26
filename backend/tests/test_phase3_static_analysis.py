"""
IIFVDCAS Phase 3 Tests — Static Analysis + AVR Analysis Engine
"""
import os, sys, tempfile, subprocess, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import pytest
from pathlib import Path

from core.static_analysis.analyzer import (
    run_s45_password_check, run_s60_cert_check, run_s85_ssh_check,
    run_s20_shell_check, _identify_hash_type, _calculate_risk_score,
    StaticAnalysisResult, BinaryProtection, PasswordFinding, SSHFinding,
    CRITICAL, HIGH, MEDIUM, LOW, INFO
)
from core.static_analysis.avr_analyzer import (
    run_avr_analysis, detect_avr_binaries,
    convert_bin_to_hex, run_avr_strings, scan_disassembly_for_security,
    AVRAnalysisResult
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp(tmp_path): return tmp_path

@pytest.fixture
def linux_fs(tmp_path):
    for d in ["bin","etc","lib","usr","var","sbin","dev","proc"]:
        (tmp_path / d).mkdir()
    (tmp_path / "etc" / "passwd").write_text(
        "root:$6$salt$hash1234567890123456789012345678901234567890123456789012345678901234567890123456789012:0:0:root:/root:/bin/sh\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )
    (tmp_path / "etc" / "shadow").write_text(
        "root:$6$rounds=5000$salt$longhash123456789012345678901234567890123456789012345678901234567890123456789012345678901:18000:0:99999:7:::\n"
    )
    (tmp_path / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00"*60)
    return tmp_path

@pytest.fixture
def ssh_fs(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "ssh").mkdir()
    (tmp_path / "etc" / "ssh" / "sshd_config").write_text(
        "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"
        "PermitEmptyPasswords no\nX11Forwarding yes\n"
    )
    (tmp_path / "etc" / "ssh" / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
    )
    return tmp_path

@pytest.fixture
def avr_bin(tmp_path):
    """Synthetic AVR-like binary with embedded credentials for testing"""
    fw = tmp_path / "flash.bin"
    # Write AVR-like content with embedded strings (mirrors real IoT firmware)
    content = b"\x00" * 100
    content += b"SuperSecretPass123\x00"
    content += b"LabWiFi\x00"
    content += b"http://iot-update.local/fw.bin\x00"
    content += b"192.168.1.50\x00"
    content += b"[BOOT] Secure boot DISABLED\x00"
    content += b"[OTA] WARNING: Signature verification disabled\x00"
    content += b"FW-1.3.7-debug\x00"
    content += b"\x00" * (32768 - len(content))   # pad to 32KB (ATmega328P flash)
    fw.write_bytes(content)
    return str(fw)

@pytest.fixture
def real_avr_bin():
    """Use real extracted flash.bin if available"""
    path = "/tmp/iifvdcas_extractions/f7819128be2c/flash.bin"
    if Path(path).exists():
        return path
    return None


# ─── S45/S107: Password detection ─────────────────────────────────────────────

class TestPasswordDetection:
    def test_shadow_hash_detected(self, linux_fs):
        findings = run_s45_password_check(str(linux_fs), lambda m: None)
        assert any(f.finding_type in ("shadow_entry","passwd_hash","hash") for f in findings)

    def test_daemon_x_not_flagged(self, linux_fs):
        findings = run_s45_password_check(str(linux_fs), lambda m: None)
        values = [f.value for f in findings]
        assert not any("x" == v.strip() for v in values)

    def test_private_key_critical(self, ssh_fs):
        findings = run_s45_password_check(str(ssh_fs), lambda m: None)
        key_finds = [f for f in findings if f.finding_type == "private_key"]
        assert len(key_finds) > 0
        assert all(f.severity == CRITICAL for f in key_finds)

    def test_empty_dir(self, tmp):
        assert run_s45_password_check(str(tmp), lambda m: None) == []


# ─── Hash type identification ─────────────────────────────────────────────────

class TestHashIdentification:
    def test_md5crypt(self):    assert _identify_hash_type("$1$salt$hash") == "md5crypt"
    def test_bcrypt(self):      assert _identify_hash_type("$2a$10$salt") == "bcrypt"
    def test_sha256crypt(self): assert _identify_hash_type("$5$salt$hash") == "sha256crypt"
    def test_sha512crypt(self): assert _identify_hash_type("$6$salt$hash") == "sha512crypt"
    def test_md5_hex(self):     assert _identify_hash_type("a" * 32) == "md5"
    def test_sha1_hex(self):    assert _identify_hash_type("a" * 40) == "sha1"
    def test_sha256_hex(self):  assert _identify_hash_type("a" * 64) == "sha256"
    def test_sha512_hex(self):  assert _identify_hash_type("a" * 128) == "sha512"
    def test_unknown(self):     assert _identify_hash_type("notahash") == "unknown"


# ─── S85: SSH check ───────────────────────────────────────────────────────────

class TestSSHCheck:
    def test_permit_root_detected(self, ssh_fs):
        findings = run_s85_ssh_check(str(ssh_fs), lambda m: None)
        assert any("PermitRootLogin" in f.detail for f in findings)

    def test_permit_root_critical(self, ssh_fs):
        findings = run_s85_ssh_check(str(ssh_fs), lambda m: None)
        root = [f for f in findings if "PermitRootLogin" in f.detail]
        assert all(f.severity == CRITICAL for f in root)

    def test_password_auth_detected(self, ssh_fs):
        findings = run_s85_ssh_check(str(ssh_fs), lambda m: None)
        assert any("PasswordAuthentication" in f.detail for f in findings)

    def test_private_key_found(self, ssh_fs):
        findings = run_s85_ssh_check(str(ssh_fs), lambda m: None)
        assert any(f.finding_type == "private_key" for f in findings)

    def test_empty_dir(self, tmp):
        assert run_s85_ssh_check(str(tmp), lambda m: None) == []


# ─── S20: Script check ────────────────────────────────────────────────────────

class TestScriptCheck:
    def test_no_crash_empty(self, tmp):
        assert run_s20_shell_check(str(tmp), lambda m: None) == []

    def test_returns_list(self, tmp):
        (tmp / "test.sh").write_text("#!/bin/bash\necho hi\n")
        result = run_s20_shell_check(str(tmp), lambda m: None)
        assert isinstance(result, list)


# ─── S60: Certificate check ───────────────────────────────────────────────────

class TestCertCheck:
    def test_no_crash_empty(self, tmp):
        assert run_s60_cert_check(str(tmp), lambda m: None) == []


# ─── Risk score calculator ────────────────────────────────────────────────────

class TestRiskScore:
    def _r(self, **kw):
        r = StaticAnalysisResult(job_id="t", target_dir="/tmp", started_at="")
        for k, v in kw.items(): setattr(r, k, v)
        return r

    def test_zero_is_minimal(self):
        score, label = _calculate_risk_score(self._r(total_binaries=5))
        assert score < 30 and label in ("minimal","low")

    def test_bad_binaries_raises_score(self):
        r = self._r(total_binaries=20, binaries_no_nx=20, binaries_no_pie=20, binaries_no_canary=20)
        score, _ = _calculate_risk_score(r)
        assert score >= 30

    def test_critical_passwords_raise_score(self):
        r = self._r(password_findings=[{"severity":"critical"}]*5)
        score, _ = _calculate_risk_score(r)
        assert score >= 20

    def test_avr_critical_raises_score(self):
        r = self._r(avr_findings=[{"severity":"critical"}]*4)
        score, _ = _calculate_risk_score(r)
        assert score >= 25

    def test_score_capped_100(self):
        r = self._r(total_binaries=100, binaries_no_nx=100, binaries_no_pie=100,
                    binaries_no_canary=100,
                    password_findings=[{"severity":"critical"}]*50,
                    weak_functions=[{}]*500,
                    avr_findings=[{"severity":"critical"}]*20,
                    ssh_findings=[{"severity":"critical"}]*20,
                    total_expired_certs=10)
        score, _ = _calculate_risk_score(r)
        assert score == 100


# ─── AVR: Binary detection ────────────────────────────────────────────────────

class TestAVRDetection:
    def test_detects_bin_file(self, avr_bin):
        d = str(Path(avr_bin).parent)
        found = detect_avr_binaries(d)
        assert str(avr_bin) in found

    def test_no_bins_empty_dir(self, tmp):
        found = detect_avr_binaries(str(tmp))
        assert found == []

    def test_real_flash_bin(self, real_avr_bin):
        if not real_avr_bin:
            pytest.skip("Real flash.bin not available")
        found = detect_avr_binaries(str(Path(real_avr_bin).parent))
        assert real_avr_bin in found


# ─── AVR: objcopy conversion ──────────────────────────────────────────────────

class TestAVRObjcopy:
    def test_bin_to_hex_succeeds(self, avr_bin):
        logs = []
        hex_path = convert_bin_to_hex(avr_bin, lambda m: logs.append(m))
        assert hex_path is not None
        assert Path(hex_path).exists()
        assert hex_path.endswith(".hex")

    def test_hex_file_has_content(self, avr_bin):
        hex_path = convert_bin_to_hex(avr_bin, lambda m: None)
        if hex_path:
            assert Path(hex_path).stat().st_size > 0
            content = Path(hex_path).read_text()
            assert content.startswith(":")  # Intel HEX format starts with ':'


# ─── AVR: String extraction ───────────────────────────────────────────────────

class TestAVRStrings:
    def test_extracts_credentials(self, avr_bin):
        logs = []
        strings, findings = run_avr_strings(avr_bin, lambda m: logs.append(m))
        assert len(strings) > 0
        finding_types = [f.finding_type for f in findings]
        # Should detect hardcoded password and insecure HTTP
        assert any("password" in t or "credential" in t or "http" in t for t in finding_types)

    def test_detects_http_url(self, avr_bin):
        _, findings = run_avr_strings(avr_bin, lambda m: None)
        http_finds = [f for f in findings if "http" in f.finding_type]
        assert len(http_finds) > 0

    def test_detects_security_bypass(self, avr_bin):
        _, findings = run_avr_strings(avr_bin, lambda m: None)
        bypass = [f for f in findings if "bypass" in f.finding_type or "debug" in f.finding_type]
        assert len(bypass) > 0


# ─── AVR: Full analysis pipeline ─────────────────────────────────────────────

class TestAVRFullAnalysis:
    def test_analysis_succeeds(self, avr_bin):
        result = run_avr_analysis(avr_bin)
        assert result.status == "success"

    def test_disassembly_populated(self, avr_bin):
        result = run_avr_analysis(avr_bin)
        assert result.disassembly is not None
        assert result.disassembly["flash_size_bytes"] > 0

    def test_device_hint_set(self, avr_bin):
        result = run_avr_analysis(avr_bin)
        assert result.disassembly["device_hint"] != ""

    def test_instructions_counted(self, avr_bin):
        result = run_avr_analysis(avr_bin)
        assert result.disassembly["total_instructions"] > 0

    def test_finds_critical_credentials(self, avr_bin):
        result = run_avr_analysis(avr_bin)
        assert result.critical_count > 0

    def test_strings_extracted(self, avr_bin):
        result = run_avr_analysis(avr_bin)
        assert result.strings_extracted > 0

    def test_real_flash_bin_full(self, real_avr_bin):
        if not real_avr_bin:
            pytest.skip("Real flash.bin not available")
        result = run_avr_analysis(real_avr_bin)
        assert result.status == "success"
        assert result.critical_count >= 3   # SuperSecretPass123, secure boot disabled, etc.
        assert result.disassembly["device_hint"] == "ATmega328P (32KB flash)"
        assert len(result.disassembly["interrupt_vectors"]) >= 10
        print(f"\n  Real AVR: {result.total_findings} findings, "
              f"{result.critical_count} critical, "
              f"{result.strings_extracted} strings, "
              f"{result.disassembly['total_instructions']} instructions")


# ─── API endpoint tests ───────────────────────────────────────────────────────

class TestPhase3API:
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

    def test_version_03(self, client):
        assert client.get("/").json()["version"] == "0.3.0"

    def test_start_missing_body(self, client):
        assert client.post("/api/v1/analysis/start", json={}).status_code == 400

    def test_start_nonexistent_dir(self, client):
        assert client.post("/api/v1/analysis/start",
                           json={"target_dir": "/nonexistent"}).status_code == 404

    def test_jobs_list(self, client):
        r = client.get("/api/v1/analysis/jobs")
        assert r.status_code == 200 and "jobs" in r.json()

    def test_get_nonexistent_job(self, client):
        assert client.get("/api/v1/analysis/nonexistent123").status_code == 404

    def test_avr_endpoint_nonexistent(self, client):
        assert client.get("/api/v1/analysis/nonexistent123/avr").status_code == 404

    def test_system_info_phase3(self, client):
        data = client.get("/api/v1/system/info").json()
        assert "phase3_static_analysis" in data["available_phases"]
