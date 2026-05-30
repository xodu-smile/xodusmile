"""
In-process demo
---------------
agent와 simulator를 같은 프로세스에서 실행해서 모든 탐지 시나리오를
한 번에 검증한다. 대시보드는 띄우지 않는다 (콘솔 출력으로 검증).

Usage:
  python demo_inproc.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from console import force_utf8
from agent import Agent
from tests.simulator import (
    populate_targets,
    simulate_encryption_pattern,
    simulate_canary_touch,
    simulate_vss_deletion,
    simulate_bcd_tamper,
)


def section(title):
    print("\n" + "─" * 60)
    print(f" {title}")
    print("─" * 60)


def main():
    force_utf8()
    watch = Path("./test_watch_dir").resolve()
    watch.mkdir(parents=True, exist_ok=True)

    # 깨끗한 상태로 시작
    for f in watch.glob("*"):
        try:
            f.unlink()
        except OSError:
            pass

    agent = Agent([str(watch)], db_path="./demo.db")

    section("STAGE 1 · Agent boot")
    agent.start()
    time.sleep(2)
    print(f"  current score: {agent.engine.current_score()} "
          f"({agent.engine.current_level().value})")

    section("STAGE 2 · Populate dummy user files (baseline)")
    populate_targets(watch, count=20)
    time.sleep(3)
    print(f"  score after baseline: {agent.engine.current_score()} "
          f"({agent.engine.current_level().value})")

    section("STAGE 3 · Simulate VSS deletion (pre-encryption)")
    simulate_vss_deletion(agent)
    time.sleep(1)
    print(f"  score: {agent.engine.current_score()} "
          f"({agent.engine.current_level().value})")

    section("STAGE 4 · Simulate BCD tampering")
    simulate_bcd_tamper(agent)
    time.sleep(1)
    print(f"  score: {agent.engine.current_score()} "
          f"({agent.engine.current_level().value})")

    section("STAGE 5 · Touch canary file")
    simulate_canary_touch(watch)
    time.sleep(2)
    print(f"  score: {agent.engine.current_score()} "
          f"({agent.engine.current_level().value})")

    section("STAGE 6 · Simulate encryption burst")
    simulate_encryption_pattern(watch, speed=0.05)
    time.sleep(3)
    print(f"  score: {agent.engine.current_score()} "
          f"({agent.engine.current_level().value})")

    section("FINAL · Stats")
    stats = agent.store.stats()
    print(f"  total signals recorded : {stats['total']}")
    print(f"  by detector            : {stats['by_detector']}")
    print(f"  by severity            : {stats['by_severity']}")

    agent.stop()


if __name__ == "__main__":
    main()
