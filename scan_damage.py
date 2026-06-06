"""
Scan Damage (디코이 불필요 피해 검사)
------------------------------------
랜섬웨어 피해를 **디코이(미끼 파일) 없이** 검사한다.

postmortem.py 는 미리 깔아둔 디코이(document_*)의 손상 여부로 피해율을 재지만,
이 도구는 디코이가 없어도 동작한다.  핵심 아이디어:

  1. **신호 기반 (정확)** — detector.db 에 기록된 탐지 신호의 metadata 에는
     랜섬웨어가 *실제로 건드린 파일 경로*가 들어 있다.  그 경로들의 현재
     상태(삭제됨/이름변경/내용손상)를 확인한다.  추측이 아니라 관측이므로
     정상 압축파일·사진을 오판하지 않는다.

  2. **전체 폴더 스캔 (보조)** — 1에서 관측된 *의심 확장자*(예: .phobos,
     .encrypted)와 랜섬노트 패턴을, 지정한 폴더 전체에서 찾는다.  실제 공격
     에서 본 확장자만 세므로, 정상 .zip/.jpg 를 암호화로 오판하지 않는다.

에이전트 코드(scoring 등)를 import 하지 않으므로 에이전트가 깨졌어도 동작한다.
표준 라이브러리만 사용.

Usage:
  python scan_damage.py                         # detector.db 의 신호만으로 검사
  python scan_damage.py --watch C:\\Users\\you\\Documents
  python scan_damage.py --db detector.db --watch C:\\data --out scan.md
"""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# 실제 암호화/파괴를 가리키는 신호 이름과, 그 metadata 에서 파일 경로가 담기는 키.
ENCRYPT_NAMES = {"high_entropy_write", "magic_bytes_lost", "modify_burst",
                 "kernel_write_burst", "process_write_burst", "canary_modified"}
RENAME_NAMES = {"suspicious_extension", "kernel_rename_burst"}
DELETE_NAMES = {"file_delete", "canary_deleted"}
PATH_KEYS = ("path", "dest", "src", "last_path", "new_path", "old_path", "target")

# 표준 파일 확장자(이게 새로 '붙은' 확장자면 암호화 의심에서 제외).
COMMON_EXTS = {
    ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".zip", ".rar", ".7z",
    ".csv", ".json", ".xml", ".html", ".htm", ".md", ".rtf", ".odt",
    ".psd", ".ai", ".eps", ".dwg", ".sql", ".db", ".bak", ".log",
}

# 랜섬노트로 보이는 파일명/확장자.
NOTE_NAME_HINTS = ("readme", "decrypt", "restore", "recover", "how_to",
                   "howto", "help_", "_help", "ransom", "unlock", "info",
                   "your_files", "files_encrypted")
NOTE_EXTS = {".txt", ".html", ".htm", ".hta"}

SESSION_GAP_SECONDS = 300


# ---------------------------------------------------------------------------
# detector.db 읽기 (postmortem.py 와 동일한 안전 스냅샷 방식)
# ---------------------------------------------------------------------------

@contextmanager
def _db_snapshot(db_path: Path):
    tmpdir = tempfile.mkdtemp(prefix="sd_db_")
    try:
        dst = Path(tmpdir) / "snapshot.db"
        shutil.copy2(db_path, dst)
        for suffix in ("-journal", "-wal", "-shm"):
            side = Path(str(db_path) + suffix)
            if side.exists():
                shutil.copy2(side, Path(str(dst) + suffix))
        yield dst
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def load_signals(db_path: Path) -> list[dict]:
    if not db_path.exists():
        return []
    rows = None
    try:
        with _db_snapshot(db_path) as snap:
            conn = sqlite3.connect(str(snap), timeout=5.0)
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM signals ORDER BY timestamp ASC").fetchall()
            finally:
                conn.close()
    except Exception as e:
        print(f"[scan_damage] 스냅샷 읽기 실패({e}); 원본 RO 로 재시도",
              file=sys.stderr)
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
            try:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM signals ORDER BY timestamp ASC").fetchall()
            finally:
                conn.close()
        except Exception as e2:
            print(f"[scan_damage] DB 읽기 실패: {e2}", file=sys.stderr)
            return []
    out = []
    for r in rows or []:
        d = dict(r)
        try:
            d["metadata"] = json.loads(d["metadata"]) if d.get("metadata") else {}
        except (json.JSONDecodeError, TypeError):
            d["metadata"] = {}
        out.append(d)
    return out


def last_session(signals: list[dict]) -> list[dict]:
    """가장 최근 세션(300초 이상 공백 전까지)만 남긴다."""
    if not signals:
        return []
    cut = 0
    for i in range(len(signals) - 1, 0, -1):
        if signals[i]["timestamp"] - signals[i - 1]["timestamp"] > SESSION_GAP_SECONDS:
            cut = i
            break
    return signals[cut:]


# ---------------------------------------------------------------------------
# 파일 검사 도우미
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _norm_path(p: str) -> str:
    """커널 디바이스 경로(\\Device\\HarddiskVolumeN\\..)를 드라이브 경로로 best-effort 변환."""
    if not p:
        return p
    m = re.match(r"\\Device\\HarddiskVolume\d+\\(.*)", p, re.IGNORECASE)
    if m:
        # 볼륨 번호 -> 드라이브 문자 매핑은 알 수 없으니 C: 로 가정(best-effort).
        return "C:\\" + m.group(1)
    return p


def _sig_paths(meta: dict) -> list[str]:
    out = []
    for k in PATH_KEYS:
        v = meta.get(k)
        if isinstance(v, str) and v:
            out.append(_norm_path(v))
    return out


def _suspicious_ext(path: str) -> Optional[str]:
    """경로의 확장자가 '비표준(암호화 의심)'이면 그 확장자를 돌려준다."""
    name = Path(path).name.lower()
    suffix = Path(name).suffix
    if not suffix:
        return None
    if suffix in COMMON_EXTS:
        return None
    # 이중 확장자(foo.docx.phobos)거나 표준이 아닌 확장자 → 의심.
    return suffix


# ---------------------------------------------------------------------------
# 1) 신호 기반 피해 집계
# ---------------------------------------------------------------------------

def damage_from_signals(signals: list[dict]) -> dict:
    encrypted: set = set()
    renamed: set = set()
    deleted: set = set()
    susp_exts: Counter = Counter()
    by_pid: Counter = Counter()

    for s in signals:
        name = s.get("name", "")
        meta = s.get("metadata") or {}
        paths = _sig_paths(meta)
        pid = meta.get("pid")
        if name in ENCRYPT_NAMES:
            encrypted.update(paths)
            if pid:
                by_pid[pid] += 1
        elif name in RENAME_NAMES:
            renamed.update(paths)
            for p in paths:
                ext = _suspicious_ext(p)
                if ext:
                    susp_exts[ext] += 1
            if pid:
                by_pid[pid] += 1
        elif name in DELETE_NAMES:
            deleted.update(paths)

    distinct = encrypted | renamed | deleted
    return {
        "encrypted": encrypted,
        "renamed": renamed,
        "deleted": deleted,
        "distinct": distinct,
        "susp_exts": susp_exts,
        "by_pid": by_pid,
    }


def verify_on_disk(paths: set) -> dict:
    """신호에 기록된 경로들의 *현재* 상태를 확인한다."""
    gone = []
    high_entropy = []
    present = []
    for p in sorted(paths):
        try:
            fp = Path(p)
            if not fp.exists():
                gone.append(p)
                continue
            present.append(p)
            ext = fp.suffix.lower()
            # 이미 압축/이미지인 확장자는 원래 고엔트로피이므로 판정에서 제외.
            if ext in {".zip", ".rar", ".7z", ".jpg", ".jpeg", ".png",
                       ".mp4", ".mov", ".mkv", ".gz", ".pdf"}:
                continue
            head = fp.read_bytes()[:4096]
            if shannon_entropy(head) > 7.5:
                high_entropy.append(p)
        except OSError:
            continue
    return {"gone": gone, "high_entropy": high_entropy, "present": present}


# ---------------------------------------------------------------------------
# 2) 전체 폴더 스캔 (의심 확장자 + 랜섬노트)
# ---------------------------------------------------------------------------

def scan_folder(watch_dirs: list[Path], susp_exts: set) -> dict:
    ext_hits: Counter = Counter()
    notes: list[str] = []
    scanned = 0
    susp_exts = {e.lower() for e in susp_exts}

    for wd in watch_dirs:
        if not wd.exists():
            continue
        for p in wd.rglob("*"):
            try:
                if not p.is_file():
                    continue
            except OSError:
                continue
            scanned += 1
            name = p.name.lower()
            suffix = p.suffix.lower()
            # 관측된 의심 확장자와 같은 확장자면 피해 후보.
            if susp_exts and suffix in susp_exts:
                ext_hits[suffix] += 1
            # 랜섬노트 후보.
            if suffix in NOTE_EXTS and any(h in name for h in NOTE_NAME_HINTS):
                if len(notes) < 50:
                    notes.append(str(p))
    return {"scanned": scanned, "ext_hits": ext_hits, "notes": notes}


# ---------------------------------------------------------------------------
# 리포트 렌더링
# ---------------------------------------------------------------------------

def render(dmg: dict, disk: dict, folder: Optional[dict],
           watch_dirs: list[Path]) -> str:
    L: list[str] = []
    def line(s=""):
        L.append(s)

    line("# 피해 검사 결과 (디코이 불필요)")
    line("")
    line(f"> 생성 시각: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    line("> 탐지 신호 기록(detector.db)과 실제 디스크 상태를 대조했습니다. "
         "미끼(디코이) 파일이 없어도 동작합니다.")
    line("")

    enc, ren, dele = dmg["encrypted"], dmg["renamed"], dmg["deleted"]
    total = len(dmg["distinct"])

    # ── 요약 ──
    line("## 한눈에 보기")
    line("")
    if total == 0 and not (folder and sum(folder["ext_hits"].values())):
        line("- ✅ **피해 정황이 발견되지 않았습니다.** 랜섬웨어가 파일을 "
             "암호화·변경·삭제한 기록이 없습니다.")
    else:
        line(f"- ⚠️ **피해 정황이 발견되었습니다.** 랜섬웨어가 건드린 것으로 "
             f"보이는 파일이 최소 **{total}개** 있습니다.")
    line(f"- 변조/암호화 정황: **{len(enc)}개** · 이름변경: **{len(ren)}개** "
         f"· 삭제: **{len(dele)}개**")
    if disk["gone"]:
        line(f"- 그중 현재 **삭제되어 사라진 파일: {len(disk['gone'])}개**")
    if disk["high_entropy"]:
        line(f"- 현재 디스크에서 **내용이 암호화된 것으로 확인된 파일: "
             f"{len(disk['high_entropy'])}개**")
    if dmg["susp_exts"]:
        tops = ", ".join(f"`{e}`×{n}" for e, n in dmg["susp_exts"].most_common(8))
        line(f"- 관측된 의심 확장자: {tops}")
    line("")

    # ── 1. 신호 기반 ──
    line("## 1. 랜섬웨어가 실제로 건드린 파일 (탐지 기록 기준)")
    line("")
    line("탐지 신호에 기록된, 랜섬웨어가 실제로 접근/변경한 파일입니다 "
         "(추측이 아니라 관측이라 정확합니다).")
    line("")
    def _list(title, items, mark):
        if not items:
            return
        line(f"**{title} ({len(items)}개)**")
        line("")
        for p in sorted(items)[:30]:
            line(f"- {mark} `{p}`")
        if len(items) > 30:
            line(f"- … 외 {len(items) - 30}개")
        line("")
    _list("내용이 변조/암호화됨", enc, "🔒")
    _list("이름/확장자가 바뀜", ren, "🏷")
    _list("삭제됨", dele, "🗑")
    if total == 0:
        line("_해당 기록이 없습니다._")
        line("")

    # 디스크 현재 상태 교차검증
    if dmg["distinct"]:
        line("### 현재 디스크 상태 확인")
        line("")
        line(f"- 위 파일 중 현재 존재: **{len(disk['present'])}개** · "
             f"사라짐(삭제): **{len(disk['gone'])}개**")
        if disk["high_entropy"]:
            line(f"- 존재하는 파일 중 **내용이 무작위 데이터(암호화 정황)**: "
                 f"**{len(disk['high_entropy'])}개**")
            for p in disk["high_entropy"][:15]:
                line(f"  - 🔒 `{p}`")
        line("")

    # ── 2. 전체 폴더 스캔 ──
    if folder is not None:
        line("## 2. 전체 폴더 스캔")
        line("")
        wd_txt = ", ".join(f"`{w}`" for w in watch_dirs)
        line(f"- 검사한 폴더: {wd_txt}")
        line(f"- 스캔한 파일 수: **{folder['scanned']}개**")
        if folder["ext_hits"]:
            line("- **관측된 의심 확장자와 같은 확장자를 가진 파일** "
                 "(랜섬웨어 피해 강력 의심):")
            for e, n in folder["ext_hits"].most_common(15):
                line(f"  - `{e}` → **{n}개**")
        else:
            line("- 의심 확장자를 가진 파일을 찾지 못했습니다.")
        if folder["notes"]:
            line(f"- **랜섬노트 후보: {len(folder['notes'])}건**")
            for n in folder["notes"][:15]:
                line(f"  - 📄 `{n}`")
        line("")
    else:
        line("## 2. 전체 폴더 스캔")
        line("")
        line("_`--watch <폴더>` 를 지정하면 폴더 전체에서 의심 확장자·랜섬노트도 "
             "함께 찾습니다._")
        line("")

    return "\n".join(L)


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="디코이 없이 랜섬웨어 피해를 검사한다.")
    ap.add_argument("--db", default="detector.db", help="신호 DB 경로")
    ap.add_argument("--watch", action="append", default=[],
                    help="전체 스캔할 폴더(여러 번 지정 가능). 생략 시 신호만으로 검사")
    ap.add_argument("--all-sessions", action="store_true",
                    help="최근 세션만이 아니라 DB 전체 신호를 검사")
    ap.add_argument("--out", default=None, help="결과 마크다운 저장 경로")
    args = ap.parse_args()

    signals = load_signals(Path(args.db))
    if not args.all_sessions:
        signals = last_session(signals)

    dmg = damage_from_signals(signals)
    disk = verify_on_disk(dmg["distinct"])

    folder = None
    watch_dirs = [Path(w) for w in args.watch]
    if watch_dirs:
        # 관측된 의심 확장자 + 신호 경로에 나타난 의심 확장자.
        susp = set(dmg["susp_exts"].keys())
        for p in dmg["renamed"] | dmg["encrypted"]:
            e = _suspicious_ext(p)
            if e:
                susp.add(e)
        folder = scan_folder(watch_dirs, susp)

    report = render(dmg, disk, folder, watch_dirs)
    print(report)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"\n[scan_damage] 저장됨: {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
