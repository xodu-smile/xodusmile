"""
Detector base class.
"""

import threading
from abc import ABC, abstractmethod

from scoring import ScoringEngine, Signal


class Detector(ABC):
    """모든 탐지기의 공통 인터페이스."""

    name: str = "base"

    def __init__(self, engine: ScoringEngine):
        self.engine = engine
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_safe, name=f"detector-{self.name}", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3.0)

    def emit(self, signal: Signal) -> None:
        self.engine.submit(signal)

    def _run_safe(self) -> None:
        try:
            self.run()
        except Exception as e:
            print(f"[{self.name}] crashed: {e}")

    @abstractmethod
    def run(self) -> None:
        """탐지 루프. self._stop_event.is_set() 을 주기적으로 확인할 것."""
        ...
