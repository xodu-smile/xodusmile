"""
Ransom Note Detector
--------------------
랜섬웨어가 암호화 전후로 각 폴더에 떨어뜨리는 **협박문(ransom note)** 을 탐지한다.

왜 재설계했는가 (기존 v1 의 두 가지 약점):

  1. **파일명만으로 판정 → 범위가 너무 좁다.**  현대 랜섬웨어의 협박문은
     ``HOW_TO_DECRYPT.txt`` 같은 정형 이름만 쓰지 않는다.  무작위 이름
     (``A7F3C.txt``), 피해자 ID 가 섞인 이름(``readme_[id].txt``), ``.hta``
     팝업 등 이름이 제각각이다.  이름 정규식만 보면 이런 노트를 통째로 놓친다.
     → **내용 기반(content-based)** 분석을 추가한다: 암호화폐 지갑 주소,
       ``.onion`` 주소, "your files have been encrypted" 류 협박 문구, 연락처
       (이메일/Tox/Telegram) 같은 협박문 고유의 *내용 지표* 를 본다.  이름이
       무엇이든 내용이 협박문이면 잡는다.

  2. **다중 확산(spread) 기준이 너무 너그럽다 → 오탐.**  v1 은 "서로 다른
     디렉터리 2개에서 이름이 매칭되는 파일"만으로 곧장 CRITICAL 을 띄웠다.
     ``readme.txt`` 두 개(정상 프로젝트 두 폴더)가 잘못 매칭되면 즉시 최고
     등급이 된다.
     → CRITICAL(``ransom_note_spread``)은 이제 다음 중 하나를 요구한다:
         (a) **내용으로 확인된**(content-confirmed) 협박문이 ≥
             ``SPREAD_DIR_THRESHOLD`` (=3) 개 디렉터리에 퍼졌거나,
         (b) 이름만 매칭된 노트가 ≥ 임계 디렉터리에 있으면서 **실제 암호화
             활동(canary 트립 / mass_io 암호화 신호)이 같은 윈도우에 동반**될 때.
       이름만으로 퍼진 것 하나로는 더 이상 CRITICAL 이 되지 않는다.

설계 (mass_io 와 동일: watchdog 이벤트 우선, 없으면 폴링 폴백):
  - watchdog 가 있으면 파일 생성/이동/수정 이벤트에서만 검사한다.
  - watchdog 가 없으면 재귀 폴링으로 폴백(작은 트리/테스트용).
  - 한 번 본 노트 경로는 다시 알리지 않는다(폭주 방지).
  - canary 가 트립하면(거의 확실한 랜섬웨어) 단일 노트도 즉시 강하게 본다.
"""

import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

from .base import Detector
from scoring import Signal, Severity, ENCRYPTION_SIGNAL_NAMES


# 협박문으로 인정할 파일 확장자 (또는 확장자 없는 README).
NOTE_EXTENSIONS = {".txt", ".html", ".htm", ".hta", ".rtf", ".url", ""}

# 협박문 파일명 패턴 (소문자 파일명 전체에 대해 검사).  특이도 높은 패턴만.
# 정상 파일(readme.md, license.txt 등)을 피하려고 "decrypt/recover/restore/
# ransom/unlock + files/data/your" 같은 강한 조합 위주로 구성한다.
_NOTE_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in (
        r"how[\s_\-]*to[\s_\-]*decrypt",
        r"how[\s_\-]*to[\s_\-]*(restore|recover|back)[\s_\-]*(files|data)",
        r"decrypt[\s_\-]*(instruction|info|files|guide|note|me)",
        r"(recover|restore|unlock)[\s_\-]*(my|your)?[\s_\-]*files",
        r"(your|all)[\s_\-]*files[\s_\-]*(are|have been)?[\s_\-]*(encrypted|locked)",
        r"ransom[\s_\-]*(note|ware|message)",
        r"!{1,3}[\s_]*(readme|read[\s_\-]*me|restore|recover|decrypt)",
        r"_readme\.txt$",                       # STOP/Djvu 패밀리
        r"read[\s_\-]*me[\s_\-]*(for|to)[\s_\-]*decrypt",
        r"(help|info)[\s_\-]*(decrypt|restore|recover)",
        r"recovery[\s_\-]*(key|info|instruction)",
        r"unlock[\s_\-]*(your|my|files|data|instruction)",
    )
]


# ---------------------------------------------------------------------------
# 내용 기반(content) 지표 — 파일명이 무엇이든 *내용* 으로 협박문을 식별한다.
# ---------------------------------------------------------------------------
# 강(strong) 지표: 정상 텍스트 파일에는 거의 나오지 않는다.  하나만 있어도
# 협박문 의심도가 크게 오른다.  약(weak) 지표: 협박문에 흔하지만 단독으로는
# 정상 문서에도 나올 수 있다(여러 개가 모여야 의미).
_RX = lambda p: re.compile(p, re.IGNORECASE)

# 암호화폐 지갑 주소 (BTC bech32/legacy, ETH, Monero).  협박문의 결정적 단서.
_CRYPTO_PATTERNS = [
    _RX(r"\bbc1[ac-hj-np-z02-9]{11,71}\b"),                 # BTC bech32
    _RX(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),            # BTC legacy
    _RX(r"\b0x[a-fA-F0-9]{40}\b"),                          # ETH
    _RX(r"\b4[0-9AB][0-9a-zA-Z]{93}\b"),                    # Monero
]
_ONION_PATTERN = _RX(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b")
# "your files have been encrypted" / "files are locked" 류 — 협박문 고유 문구.
_ENCRYPTED_PHRASES = [
    _RX(r"(your|all|the)\s+(files|data|documents|network|important\s+files)"
        r"\s+(have\s+been|are|were|has\s+been)\s+(encrypted|locked|stolen)"),
    _RX(r"\b(files?|data)\s+(are|is|have\s+been)?\s*encrypted\b"),
]
# 복호화/결제 유도 문구.
_DECRYPT_PHRASES = [
    _RX(r"decrypt(ion)?\s+(key|tool|software|service|password)"),
    _RX(r"(recover|restore)\s+(your|all|the)\s+(files|data|documents)"),
    _RX(r"\bhow\s+to\s+(decrypt|recover|restore)\b"),
]
# 결제/랜섬 용어.
_PAYMENT_TERMS = _RX(
    r"\b(bitcoin|btc|monero|xmr|ethereum|tor\s+browser|"
    r"ransom|payment|wallet\s+address|pay\s+(the|us|a)\b)"
)
# 연락 채널.
_CONTACT_TERMS = _RX(
    r"([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}"          # email
    r"|\btox\s*id\b|\bqtox\b|\bsession\s*id\b|telegram|jabber|protonmail|tutanota)"
)
# 협박/압박 문구.
_THREAT_TERMS = _RX(
    r"(do\s+not\s+(rename|modify|move|delete)|"
    r"\bdeadline\b|permanently\s+(lost|deleted)|"
    r"(leak|publish|sell)\s+(your|the)\s+(data|files)|"
    r"price\s+will\s+(double|increase))"
)

# 내용 점수 임계 — 강 지표(암호화폐/onion, 가중치 2) 최소 1개 + 합이 이 값
# 이상이면 "내용으로 확인된" 협박문.  약 지표(가중치 1)만으로는 confirmed 불가.
CONTENT_CONFIRM_SCORE = 3


# 가중치 / 임계값
W_NOTE_CONFIRMED = 45     # 내용 확인된 단일 협박문 (HIGH)
W_NOTE_NAMEONLY = 15      # 이름만 매칭된 단일 후보 (MEDIUM) — 단독으론 약하게
W_NOTE_SPREAD = 90        # 다중 디렉터리 확산 (CRITICAL) — 단발로 임계 근접
SPREAD_DIR_THRESHOLD = 3  # 서로 다른 디렉터리 이 개수 이상이면 spread (v1 의 2 → 3)
SPREAD_WINDOW_SEC = 60.0  # 이 시간 안에 모인 노트만 확산으로 집계
MAX_NOTE_BYTES = 65536    # 이보다 큰 파일은 협박문이 아니라고 보고 제외(보통 짧다)
POLL_INTERVAL = 2.0
# _seen_notes 가 장기 실행에서 무한정 커지지 않도록 상한(초과 시 초기화).
_SEEN_CAP = 20000


@dataclass
class ContentVerdict:
    """협박문 내용 분석 결과."""
    score: int = 0
    confirmed: bool = False
    indicators: List[str] = field(default_factory=list)


def is_ransom_note_name(filename: str) -> bool:
    """파일명이 협박문 패턴과 일치하는지."""
    fn = (filename or "").lower()
    return any(p.search(fn) for p in _NOTE_PATTERNS)


def analyze_note_content(text: str) -> ContentVerdict:
    """파일 내용에서 협박문 지표를 찾아 점수화한다.

    파일명이 무엇이든 *내용* 만으로 협박문 여부를 판단하기 위한 핵심 함수.
    정상 문서(라이선스/메모/소스코드)는 강 지표가 없고 약 지표도 거의 없어
    confirmed 가 되지 않는다.
    """
    v = ContentVerdict()
    if not text:
        return v
    strong = 0

    # 강(strong) 지표 — 정상 문서에는 사실상 절대 나오지 않는다: 암호화폐
    # 지갑 주소, Tor .onion 주소.  내용 확인(confirmed)은 *반드시* 이 중
    # 하나를 요구한다.  IT/보안 문서가 "files are encrypted at rest" 같은 문구
    # 여러 개를 담아도 강 지표가 없으면 confirmed 되지 않아 오탐을 막는다.
    if any(p.search(text) for p in _CRYPTO_PATTERNS):
        v.score += 2; strong += 1; v.indicators.append("crypto_address")
    if _ONION_PATTERN.search(text):
        v.score += 2; strong += 1; v.indicators.append("onion_url")

    # 약(weak) 지표 — 협박문에 흔하지만 정상 문서에도 나올 수 있다.
    if any(p.search(text) for p in _ENCRYPTED_PHRASES):
        v.score += 1; v.indicators.append("encryption_phrase")
    if any(p.search(text) for p in _DECRYPT_PHRASES):
        v.score += 1; v.indicators.append("decrypt_instruction")
    if _PAYMENT_TERMS.search(text):
        v.score += 1; v.indicators.append("payment_terms")
    if _CONTACT_TERMS.search(text):
        v.score += 1; v.indicators.append("contact_channel")
    if _THREAT_TERMS.search(text):
        v.score += 1; v.indicators.append("threat_language")

    # confirmed: 강 지표(암호화폐/onion) 최소 1개 + 합 임계 이상.  강 지표 없이
    # 약 지표만 쌓아 confirmed 되는 경로는 의도적으로 제거(IR/보안 문서 오탐 방지).
    v.confirmed = strong >= 1 and v.score >= CONTENT_CONFIRM_SCORE
    return v


def _decode_best_effort(data: bytes) -> str:
    """협박문 본문을 텍스트로 디코드(UTF-8 → UTF-16 → latin-1 폴백)."""
    if not data:
        return ""
    if b"\x00" in data[:64]:                 # UTF-16 BOM/널바이트 패턴
        for enc in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, LookupError):
                pass
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc, errors="ignore")
        except (UnicodeDecodeError, LookupError):
            continue
    return ""


class RansomNoteDetector(Detector):
    name = "ransom_note"

    def __init__(self, engine, watch_dirs: List[str], poll_interval: float = POLL_INTERVAL):
        super().__init__(engine)
        self.watch_dirs = [Path(d) for d in watch_dirs]
        self.poll_interval = poll_interval
        self._lock = threading.Lock()
        # 이미 알린 노트 경로(소문자) — 재알림 방지.
        self._seen_notes: Set[str] = set()
        # 최근 관측한 디렉터리 -> (시각, content_confirmed).  확산 판정용.
        self._recent_dirs: Dict[str, Tuple[float, bool]] = {}
        self._observer = None
        # canary 트립 부스트(거의 확실한 랜섬웨어면 단일 노트도 강하게 본다).
        self._canary_tripped_at = 0.0
        engine.subscribe(self._on_engine_signal)

    # ---- canary 교차 신호 ----

    def _on_engine_signal(self, sig, score, level) -> None:
        if sig.detector == "canary":
            self._canary_tripped_at = time.time()

    def _boost_active(self) -> bool:
        return (time.time() - self._canary_tripped_at) < 30.0

    def _external_encryption_active(self) -> bool:
        """협박문 외의 실제 암호화 신호(canary/mass_io/kernel)가 윈도우에 있는지.

        이름만 매칭된 노트의 확산을 CRITICAL 로 승격할지 판단하는 상관(corroboration)
        기준.  노트 자신의 신호(ransom_note_*)는 제외한다 — 노트가 노트를
        보강하는 순환을 막기 위함.  신뢰 actor 의 신호도 제외.
        """
        note_names = {"ransom_note_dropped", "ransom_note_spread"}
        for s in self.engine.recent_signals(limit=120):
            if s.name in note_names:
                continue
            if s.name in ENCRYPTION_SIGNAL_NAMES and not (s.metadata or {}).get("actor_trusted"):
                return True
        return False

    # ---- detector loop ----

    def run(self) -> None:
        # 시작 시점에 이미 있던 파일은 baseline 으로 등록(과거 노트로 알람 안 뜨게).
        self._scan(initial=True)

        if HAS_WATCHDOG:
            handler = _NoteHandler(self)
            self._observer = Observer()
            for d in self.watch_dirs:
                try:
                    d.mkdir(parents=True, exist_ok=True)
                    self._observer.schedule(handler, str(d), recursive=True)
                except OSError as e:
                    print(f"[{self.name}] cannot watch {d}: {e}")
            self._observer.start()
            print(f"[{self.name}] watching {len(self.watch_dirs)} directories "
                  f"(event-driven, content-aware)")
            try:
                while not self._stop_event.is_set():
                    self._stop_event.wait(self.poll_interval)
                    self._prune(time.time())
            finally:
                self._observer.stop()
                self._observer.join(timeout=3.0)
            return

        # watchdog 미설치 — 폴링 폴백(작은 트리/테스트용).
        print(f"[{self.name}] watchdog not installed; falling back to polling")
        while not self._stop_event.is_set():
            try:
                self._scan(initial=False)
            except Exception as e:
                print(f"[{self.name}] scan error: {e}")
            self._stop_event.wait(self.poll_interval)

    def _prune(self, now: float) -> None:
        """확산 윈도우 밖의 디렉터리 관측을 정리한다(스레드 세이프)."""
        cutoff = now - SPREAD_WINDOW_SEC
        with self._lock:
            self._recent_dirs = {d: v for d, v in self._recent_dirs.items()
                                 if v[0] >= cutoff}

    def _scan(self, initial: bool) -> None:
        """폴링 경로(및 시작 baseline): 감시 트리를 훑어 신규 노트를 검사한다."""
        self._prune(time.time())
        for base in self.watch_dirs:
            if not base.exists():
                continue
            for p in self._iter_files(base):
                self._consider_path(p, initial=initial)

    @staticmethod
    def _iter_files(base: Path):
        try:
            yield from (p for p in base.rglob("*") if p.is_file())
        except OSError:
            return

    def _consider_path(self, path: Path, initial: bool = False) -> None:
        """한 경로가 신규 협박문인지 판정하고, 맞으면 신호를 발생시킨다.

        watchdog 핸들러와 폴링 스캔이 공유하는 단일 판정 지점.

        후보 선정:
          - 확장자가 노트 확장자 집합에 있고 크기가 상한 이하인 파일만 본다.
          - 후보면 내용을 읽어 analyze_note_content 로 점수화한다.
          - 이름 매칭(name_match) 또는 내용 확인(content.confirmed) 중 하나라도
            성립하면 협박문으로 취급한다 → 이름이 무작위여도 내용으로 잡는다.
        """
        key = str(path).lower()
        with self._lock:
            if key in self._seen_notes:
                return
        if path.suffix.lower() not in NOTE_EXTENSIONS:
            return
        try:
            # 심볼릭 링크/특수 파일은 거부한다 — 링크를 통해 watch 트리 밖의
            # 임의 파일(또는 /dev/zero 같은 특수 장치)을 읽게 되는 것을 막는다.
            if path.is_symlink() or not path.is_file():
                return
            if path.stat().st_size > MAX_NOTE_BYTES:
                return
        except OSError:
            return

        name_match = is_ransom_note_name(path.name)

        # 내용 분석: 이름 매칭 여부와 무관하게 후보 파일은 읽어서 본다.
        # 크기 검사를 통과해도 실제 읽기는 MAX_NOTE_BYTES 로 하드캡한다(TOCTOU
        # 로 파일이 그새 커져도 메모리 폭주가 없게).
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_NOTE_BYTES)
        except OSError:
            return
        content = analyze_note_content(_decode_best_effort(data))

        # 협박문 판정: 이름 매칭 또는 내용 확인 중 하나라도.
        if not (name_match or content.confirmed):
            return

        with self._lock:
            if key in self._seen_notes:        # 더블체크(경합 방지)
                return
            self._seen_notes.add(key)
            if len(self._seen_notes) > _SEEN_CAP:
                self._seen_notes = set()       # 메모리 상한(드물게 도달)
                self._seen_notes.add(key)
        if initial:
            # baseline — 알리지 않고 기록만.
            return
        self._handle_note(path, time.time(), name_match, content)

    def _handle_note(self, path: Path, now: float,
                     name_match: bool, content: ContentVerdict) -> None:
        directory = str(path.parent).lower()
        with self._lock:
            prev = self._recent_dirs.get(directory)
            confirmed_here = content.confirmed or (prev[1] if prev else False)
            self._recent_dirs[directory] = (now, confirmed_here)
            total_dirs = len(self._recent_dirs)
            confirmed_dirs = sum(1 for _, c in self._recent_dirs.values() if c)

        # ---- 확산(spread) 판정 — 두 경로 중 하나라도 만족하면 CRITICAL ----
        #   (a) 내용 확인된 노트가 임계 디렉터리 이상에 퍼짐, 또는
        #   (b) (이름만이라도) 노트가 임계 디렉터리 이상 + 실제 암호화 활동 동반.
        spread_by_content = confirmed_dirs >= SPREAD_DIR_THRESHOLD
        spread_by_corr = (total_dirs >= SPREAD_DIR_THRESHOLD
                          and self._external_encryption_active())
        if spread_by_content or spread_by_corr:
            self.emit(Signal(
                detector=self.name,
                name="ransom_note_spread",
                weight=W_NOTE_SPREAD,
                severity=Severity.CRITICAL,
                message=(f"Ransom note spread across {total_dirs} directories "
                         f"({confirmed_dirs} content-confirmed; latest: {path.name})"),
                metadata={
                    "path": str(path),
                    "directory": str(path.parent),
                    "directories_affected": total_dirs,
                    "directories_confirmed": confirmed_dirs,
                    "trigger": "content" if spread_by_content else "correlated",
                    "indicators": content.indicators,
                    "window_sec": SPREAD_WINDOW_SEC,
                },
            ))
            return

        # ---- 단일 노트 ----
        boosted = self._boost_active()
        if content.confirmed or boosted:
            # 내용으로 확인됐거나 canary 부스트 중 — HIGH(부스트면 CRITICAL).
            self.emit(Signal(
                detector=self.name,
                name="ransom_note_dropped",
                weight=W_NOTE_SPREAD if boosted else W_NOTE_CONFIRMED,
                severity=Severity.CRITICAL if boosted else Severity.HIGH,
                message=(f"Ransom note created: {path.name}"
                         + (" (canary already tripped)" if boosted else "")
                         + (f" [{', '.join(content.indicators)}]"
                            if content.indicators else "")),
                metadata={
                    "path": str(path),
                    "directory": str(path.parent),
                    "canary_boost": boosted,
                    "content_confirmed": content.confirmed,
                    "content_score": content.score,
                    "indicators": content.indicators,
                },
            ))
            return

        # 이름만 매칭(내용 미확인) — 약한 단발 힌트(MEDIUM).  단독으로는 위협이
        # 아니며, 같은 윈도우의 다른 신호와 합산될 때에만 의미를 갖는다.
        self.emit(Signal(
            detector=self.name,
            name="ransom_note_dropped",
            weight=W_NOTE_NAMEONLY,
            severity=Severity.MEDIUM,
            message=f"Possible ransom note (name match, unconfirmed content): {path.name}",
            metadata={
                "path": str(path),
                "directory": str(path.parent),
                "canary_boost": False,
                "content_confirmed": False,
                "content_score": content.score,
                "indicators": content.indicators,
            },
        ))


if HAS_WATCHDOG:
    class _NoteHandler(FileSystemEventHandler):
        """파일 생성/이동/수정 이벤트에서만 협박문 판정을 돌린다."""

        def __init__(self, det: "RansomNoteDetector"):
            self.det = det

        def on_created(self, event):
            if not event.is_directory:
                self.det._consider_path(Path(event.src_path))

        def on_moved(self, event):
            if not event.is_directory:
                self.det._consider_path(Path(event.dest_path))

        def on_modified(self, event):
            if not event.is_directory:
                self.det._consider_path(Path(event.src_path))
