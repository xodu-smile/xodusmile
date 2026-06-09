"""
Test Simulator
--------------
교육/연구 목적: 탐지 엔진의 반응을 검증하기 위해 랜섬웨어가 발생시킬
"행위 패턴"만 안전하게 모방한다.

** 이 도구는 실제 파일을 암호화하지 않는다. **
   - 더미 파일에 랜덤 바이트(고엔트로피)를 쓰고 .encrypted로 이름만 바꾼다
   - VSS 삭제는 실제 명령을 실행하지 않고 ProcessCmdlineDetector에
     이벤트를 직접 주입하는 방식으로 시뮬레이션한다
   - Canary 파일에 빈 쓰기로 변경 알림만 트리거한다

다른 사람의 시스템에서 절대 실행하지 말 것. 자기 격리 환경 전용.
"""

import argparse
import os
import sys
import time
from pathlib import Path

# 부모 디렉토리를 import path에 추가 (단독 실행 가능하도록)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from console import force_utf8


def populate_targets(directory: Path, count: int = 30) -> list[Path]:
    """탐지 대상이 될 더미 사용자 파일 생성."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    extensions = [".docx", ".xlsx", ".pdf", ".jpg", ".txt"]
    # 정상 매직바이트로 시작하는 더미 파일들 (PE/PDF/Office 모방)
    fake_pdf = b"%PDF-1.4\n" + b"normal pdf content " * 80
    fake_docx = b"PK\x03\x04" + b"normal office data " * 80
    fake_jpg = b"\xff\xd8\xff\xe0" + b"normal image data " * 80
    fake_txt = b"normal user document content " * 50
    payloads = [fake_docx, fake_docx, fake_pdf, fake_jpg, fake_txt]

    for i in range(count):
        ext = extensions[i % len(extensions)]
        payload = payloads[i % len(payloads)]
        p = directory / f"document_{i:03d}{ext}"
        p.write_bytes(payload)
        paths.append(p)
    print(f"[sim] populated {count} dummy target files in {directory}")
    return paths


def simulate_encryption_pattern(directory: Path, speed: float = 0.05) -> None:
    """
    랜섬웨어 행위를 모방:
      1. 각 파일을 읽고
      2. 무작위 바이트(고엔트로피)로 덮어쓰고
      3. .encrypted 확장자로 이름 변경
    실제 키 기반 암호화는 수행하지 않음 (단순 랜덤화).
    """
    targets = sorted(directory.glob("document_*"))
    if not targets:
        print("[sim] no targets found; run populate first")
        return
    print(f"[sim] simulating encryption pattern on {len(targets)} files "
          f"(speed={speed}s/file)")
    for p in targets:
        if p.suffix == ".encrypted":
            continue
        try:
            random_bytes = os.urandom(p.stat().st_size or 4096)
            p.write_bytes(random_bytes)             # 고엔트로피 쓰기
            new_path = p.with_suffix(p.suffix + ".encrypted")
            p.rename(new_path)                      # 의심스러운 확장자
        except OSError as e:
            print(f"[sim] error on {p.name}: {e}")
        time.sleep(speed)
    print("[sim] encryption pattern simulation complete")


def simulate_canary_touch(directory: Path) -> None:
    """Canary 파일을 살짝 건드려 변경 감지 트리거."""
    candidates = list(directory.glob("!*"))  + \
                 list(directory.glob("0_*")) + \
                 list(directory.glob("00_*")) + \
                 list(directory.glob("~$*")) + \
                 list(directory.glob("zzz*"))
    if not candidates:
        print(f"[sim] no canary files in {directory}; "
              f"agent may not have deployed yet")
        return
    target = candidates[0]
    print(f"[sim] modifying canary: {target.name}")
    try:
        with open(target, "ab") as f:
            f.write(b"\x00")
    except OSError as e:
        print(f"[sim] failed: {e}")


def simulate_vss_deletion(agent) -> None:
    """
    프로세스 모니터에 가짜 vssadmin 호출 이벤트 주입.
    실제로 vssadmin을 실행하지 않는다 — 시스템 손상 위험 차단.
    """
    print("[sim] injecting fake vssadmin command-line event")
    agent.proc.submit_external(
        process_name="vssadmin.exe",
        cmdline="vssadmin.exe delete shadows /all /quiet",
        pid=99999, ppid=99998,
    )


def simulate_bcd_tamper(agent) -> None:
    print("[sim] injecting fake bcdedit command-line event")
    agent.proc.submit_external(
        process_name="bcdedit.exe",
        cmdline="bcdedit /set {default} recoveryenabled no",
        pid=99997, ppid=99998,
    )


def main():
    force_utf8()
    parser = argparse.ArgumentParser(
        description="Detection engine test simulator (NO real encryption)"
    )
    parser.add_argument(
        "--dir", default="./test_watch_dir",
        help="Watch directory used by the agent",
    )
    parser.add_argument(
        "--scenario", default="full",
        choices=["populate", "encrypt", "canary", "vss",
                 "bcd", "full", "stealth"],
        help="Which scenario to simulate",
    )
    parser.add_argument(
        "--speed", type=float, default=0.05,
        help="Seconds between file ops in encrypt scenario",
    )
    args = parser.parse_args()

    directory = Path(args.dir).resolve()

    if args.scenario in ("populate", "full", "stealth"):
        populate_targets(directory, count=30)
        time.sleep(2)  # agent에게 baseline 학습 시간 주기

    if args.scenario in ("vss", "full"):
        # vss/bcd 시나리오는 같은 프로세스에서 agent 인스턴스가 필요.
        # 여기서는 별도 데모 모드를 안내한다.
        print("[sim] vss/bcd scenarios require running the simulator in the "
              "same process as the agent — see demo_inproc.py")

    if args.scenario in ("canary", "full"):
        time.sleep(1)
        simulate_canary_touch(directory)

    if args.scenario in ("encrypt", "full"):
        time.sleep(2)
        simulate_encryption_pattern(directory, speed=args.speed)

    if args.scenario == "stealth":
        # intermittent 형태 — 더 느린 페이스로
        time.sleep(2)
        simulate_encryption_pattern(directory, speed=0.5)


if __name__ == "__main__":
    main()
