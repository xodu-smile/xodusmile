"""
Post-mortem
-----------
검체를 터뜨린 뒤(detonate) RansomGuard EDR 의 성적을 집계한다.

검체가 에이전트를 죽이거나 BSOD 가 났을 수 있으므로, 메모리(in-process
responder history)가 아니라 **디스크에 영속된 증거**만 읽는다:

  1. detector.db   — signals 테이블(시그널마다 동기 기록, score_after/
                     level_after 포함). 탐지 타임라인·지연의 근거.
  2. reports/*.md  — quarantine/terminate 가 실제로 일어났을 때만 쓰인
                     인시던트 리포트. 각 파일에 raw action JSON 이 들어 있음.
  3. watch dir     — 디코이 파일이 실제로 암호화/이름변경 됐는지 스캔해
                     "탐지가 늦어 몇 개가 당했나"를 측정.

프로젝트 모듈을 import 하지 않으므로(에이전트 코드가 깨졌어도 동작),
표준 라이브러리만 쓴다.

Usage:
  python postmortem.py --watch C:\\Users\\you\\Documents
  python postmortem.py --db detector.db --reports-dir reports --out postmortem.md
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional

# 한국어/UTF-8 콘솔이 아니어도(cp949 등) 출력이 죽지 않게 한다.
# --out 파일은 항상 UTF-8 로 저장된다.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# 심각도 순서 (낮음 → 높음)
SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# simulator.py / lab_preflight.ps1 가 만드는 디코이의 원본 매직바이트.
ORIG_MAGIC = {
    ".docx": b"PK\x03\x04",
    ".pdf":  b"%PDF",
    ".jpg":  b"\xff\xd8\xff",
    ".txt":  None,            # 텍스트는 매직바이트 없음 — 엔트로피로 판정
}
ORIG_EXTS = set(ORIG_MAGIC.keys())
DECOY_RE = re.compile(r"^document_(\d+)", re.IGNORECASE)

# 랜섬노트로 보이는 파일명 힌트.
NOTE_NAME_HINTS = ("readme", "decrypt", "restore", "recover",
                   "how_to", "howto", "help_", "_help", "ransom", "unlock")
NOTE_EXTS = {".txt", ".html", ".htm", ".hta"}

# 세션 분리용 시간 간격(초). 이보다 긴 공백이 있으면 이전 실행으로 간주.
SESSION_GAP_SECONDS = 300


# ---------------------------------------------------------------------------
# detector.db 읽기
# ---------------------------------------------------------------------------

def load_signals(db_path: Path, since: Optional[float]) -> list[dict]:
    """signals 테이블을 시간순으로 읽는다. since 가 주어지면 그 이후만."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        if since is not None:
            rows = conn.execute(
                "SELECT * FROM signals WHERE timestamp >= ? ORDER BY timestamp ASC",
                (since,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM signals ORDER BY timestamp ASC"
            ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["metadata"] = json.loads(d["metadata"]) if d.get("metadata") else {}
        except (json.JSONDecodeError, TypeError):
            d["metadata"] = {}
        out.append(d)
    return out


def isolate_last_session(signals: list[dict]) -> list[dict]:
    """가장 최근 '세션'만 남긴다 — 시간 공백(SESSION_GAP_SECONDS)으로 분리.

    detector.db 에 이전 실행/데모의 시그널이 섞여 있을 수 있어, 마지막
    연속 구간만 분석 대상으로 삼는다.
    """
    if not signals:
        return signals
    start = 0
    for i in range(1, len(signals)):
        gap = signals[i]["timestamp"] - signals[i - 1]["timestamp"]
        if gap > SESSION_GAP_SECONDS:
            start = i
    return signals[start:]


# ---------------------------------------------------------------------------
# 탐지 타임라인 / 지연
# ---------------------------------------------------------------------------

# "암호화 행위"로 볼 만한 시그널(공격 시작 시점 추정용).
ENCRYPTION_HINT = re.compile(
    r"mass|entropy|magic|encrypt|rename|extension|burst|canary",
    re.IGNORECASE,
)


def first_where(signals: list[dict], pred) -> Optional[dict]:
    for s in signals:
        if pred(s):
            return s
    return None


def build_timeline(signals: list[dict]) -> dict:
    if not signals:
        return {}
    t0 = signals[0]["timestamp"]
    t_end = signals[-1]["timestamp"]

    first_enc = first_where(
        signals,
        lambda s: ENCRYPTION_HINT.search(f"{s['detector']} {s['name']} {s['message']}"),
    )
    attack_start = first_enc["timestamp"] if first_enc else t0

    first_high = first_where(
        signals, lambda s: SEV_ORDER.get(s["level_after"], 0) >= SEV_ORDER["HIGH"])
    first_crit = first_where(
        signals, lambda s: s["level_after"] == "CRITICAL")
    peak = max(signals, key=lambda s: s["score_after"])

    return {
        "t0": t0,
        "t_end": t_end,
        "attack_start": attack_start,
        "first_enc": first_enc,
        "first_high": first_high,
        "first_crit": first_crit,
        "peak_score": peak["score_after"],
        "peak_at": peak["timestamp"],
        "duration": t_end - t0,
    }


# ---------------------------------------------------------------------------
# reports/ 의 인시던트(실제 대응) 파싱
# ---------------------------------------------------------------------------

JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


def load_actions(reports_dir: Path, window: Optional[tuple[float, float]]) -> list[dict]:
    """reports/*.md 안의 raw action JSON 을 모은다. window 로 시간 필터."""
    if not reports_dir.exists():
        return []
    actions = []
    for md in sorted(reports_dir.glob("incident_*.md")):
        try:
            text = md.read_text(encoding="utf-8")
        except OSError:
            continue
        m = JSON_BLOCK_RE.search(text)
        if not m:
            continue
        try:
            act = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        ts = act.get("timestamp")
        if window and isinstance(ts, (int, float)):
            lo, hi = window
            if ts < lo - 5 or ts > hi + 120:   # 약간의 여유
                continue
        act["_file"] = md.name
        actions.append(act)
    actions.sort(key=lambda a: a.get("timestamp", 0))
    return actions


# ---------------------------------------------------------------------------
# watch dir 피해 평가
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def assess_damage(watch_dirs: list[Path], first_action_ts: Optional[float]) -> dict:
    """디코이(document_*) 파일이 손상됐는지 분류하고 새 확장자/노트를 찾는다."""
    intact = 0
    damaged = 0
    damaged_after_response = 0
    susp_exts: Counter = Counter()
    notes: list[str] = []
    scanned = 0

    for wd in watch_dirs:
        if not wd.exists():
            continue
        for p in wd.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()

            # 랜섬노트 후보
            if (p.suffix.lower() in NOTE_EXTS
                    and any(h in name for h in NOTE_NAME_HINTS)):
                if len(notes) < 20:
                    notes.append(str(p))

            # 디코이만 손상 판정 (원본을 우리가 알기 때문에 정확)
            if not DECOY_RE.match(p.name):
                continue
            scanned += 1

            ext = p.suffix.lower()
            is_damaged = False

            if ext not in ORIG_EXTS:
                # 이름이 바뀌었거나 확장자가 덧붙음 → 암호화 흔적
                is_damaged = True
                susp_exts[ext] += 1
            else:
                try:
                    head = p.read_bytes()[:4096]
                except OSError:
                    head = b""
                magic = ORIG_MAGIC.get(ext)
                if magic is not None and not head.startswith(magic):
                    is_damaged = True            # 매직바이트 파괴
                elif shannon_entropy(head) > 7.5:
                    is_damaged = True            # 고엔트로피 = 암호화/압축

            if is_damaged:
                damaged += 1
                if first_action_ts is not None:
                    try:
                        if p.stat().st_mtime >= first_action_ts:
                            damaged_after_response += 1
                    except OSError:
                        pass
            else:
                intact += 1

    return {
        "scanned": scanned,
        "intact": intact,
        "damaged": damaged,
        "damaged_after_response": damaged_after_response,
        "suspicious_exts": susp_exts,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# 리포트 렌더링
# ---------------------------------------------------------------------------

def fmt_ts(ts: Optional[float]) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_delta(a: Optional[float], b: Optional[float]) -> str:
    """b 기준 a 까지 걸린 시간."""
    if not a or not b:
        return "—"
    d = a - b
    return f"{d:+.1f}s"


def render(signals, tl, actions, damage, args) -> str:
    L: list[str] = []
    def line(s=""): L.append(s)

    line("# RansomGuard 검체 Post-mortem")
    line("")
    line(f"- 생성: {fmt_ts(time.time())}")
    line(f"- DB: `{args.db}`  ·  reports: `{args.reports_dir}`  ·  "
         f"watch: {', '.join(args.watch)}")
    line("")

    if not signals:
        line("> [!] 분석할 시그널이 없습니다. detector.db 가 비었거나 경로가 "
             "틀렸거나, 검체가 아무 탐지도 트리거하지 않았습니다(안티VM?).")
        line("")

    # ── 1. 탐지 타임라인 ────────────────────────────────────────────
    line("## 1. 탐지 타임라인 / 지연")
    line("")
    if tl:
        line("| 이벤트 | 시각 | 공격시작 기준 |")
        line("|--------|------|----------------|")
        line(f"| 첫 시그널 | {fmt_ts(tl['t0'])} | {fmt_delta(tl['t0'], tl['attack_start'])} |")
        fe = tl["first_enc"]
        line(f"| 암호화 행위 첫 감지 | {fmt_ts(tl['attack_start'])} | "
             f"{'(기준)' if fe else 'n/a'} |")
        fh = tl["first_high"]
        line(f"| HIGH 도달 | {fmt_ts(fh['timestamp']) if fh else '—'} | "
             f"{fmt_delta(fh['timestamp'] if fh else None, tl['attack_start'])} |")
        fc = tl["first_crit"]
        line(f"| CRITICAL 도달 | {fmt_ts(fc['timestamp']) if fc else '—'} | "
             f"{fmt_delta(fc['timestamp'] if fc else None, tl['attack_start'])} |")
        first_act_ts = actions[0]["timestamp"] if actions else None
        line(f"| 첫 대응(quarantine/kill) | {fmt_ts(first_act_ts)} | "
             f"{fmt_delta(first_act_ts, tl['attack_start'])} |")
        line(f"| 최고 점수 | {fmt_ts(tl['peak_at'])} (score={tl['peak_score']}) | "
             f"{fmt_delta(tl['peak_at'], tl['attack_start'])} |")
        line("")
        # 핵심 지표
        if fh:
            line(f"**탐지 지연 (공격시작→HIGH): "
                 f"{fh['timestamp'] - tl['attack_start']:.1f}s**")
        if first_act_ts:
            line(f"**대응 지연 (공격시작→첫 차단): "
                 f"{first_act_ts - tl['attack_start']:.1f}s**")
        line("")
    else:
        line("_타임라인 없음._")
        line("")

    # ── 2. 탐지기별 / 심각도별 ──────────────────────────────────────
    line("## 2. 탐지기 / 심각도 분포")
    line("")
    by_det = Counter(s["detector"] for s in signals)
    by_sev = Counter(s["severity"] for s in signals)
    line(f"- 총 시그널: **{len(signals)}**")
    if by_det:
        line("- 탐지기별: " + ", ".join(f"`{k}`={v}" for k, v in by_det.most_common()))
    if by_sev:
        order = sorted(by_sev, key=lambda k: SEV_ORDER.get(k, 0), reverse=True)
        line("- 심각도별: " + ", ".join(f"{k}={by_sev[k]}" for k in order))
    # 커널 차단 관측
    blocks = [s for s in signals
              if re.search(r"block|denied|quarantin", f"{s['name']} {s['message']}", re.I)]
    line(f"- 차단/거부 관련 시그널: **{len(blocks)}**")
    line("")

    # ── 3. 대응 효과 ────────────────────────────────────────────────
    line("## 3. 대응 효과 (reports/)")
    line("")
    if actions:
        quar = [a for a in actions if a.get("quarantined")]
        kill = [a for a in actions if a.get("terminated")]
        errs = [a for a in actions if a.get("error")]
        pids = sorted({a.get("pid") for a in actions if a.get("pid")})
        line(f"- 대응 인시던트: **{len(actions)}**  "
             f"(고유 PID {len(pids)})")
        line(f"- Quarantine 성공: **{len(quar)}**  ·  Terminate 성공: **{len(kill)}**")
        if errs:
            line(f"- 오류 동반: {len(errs)}")
        line("")
        line("| 시각 | PID | 프로세스 | quarantine | terminate | reason | error |")
        line("|------|-----|----------|-----------|-----------|--------|-------|")
        for a in actions[:40]:
            line(f"| {time.strftime('%H:%M:%S', time.localtime(a.get('timestamp', 0)))} "
                 f"| {a.get('pid','?')} | {a.get('process_name') or '?'} "
                 f"| {'Y' if a.get('quarantined') else '·'} "
                 f"| {'Y' if a.get('terminated') else '·'} "
                 f"| {(a.get('reason') or '')[:40]} "
                 f"| {(a.get('error') or '')[:40]} |")
        line("")
    else:
        line("_대응 리포트가 없습니다 — 임계치 미달이었거나, 대응 전에 "
             "에이전트가 죽었거나, responder 모드가 off 였습니다._")
        line("")

    # ── 4. 피해 평가 ────────────────────────────────────────────────
    line("## 4. 피해 평가 (watch dir 디코이)")
    line("")
    d = damage
    if d["scanned"] == 0:
        line("_디코이 파일(document_*)을 찾지 못했습니다. --watch 경로를 "
             "확인하거나, preflight 로 디코이를 먼저 채우세요._")
    else:
        total = d["scanned"]
        pct = (d["damaged"] / total * 100) if total else 0
        line(f"- 스캔된 디코이: **{total}**")
        line(f"- 손상(암호화/이름변경): **{d['damaged']}** ({pct:.0f}%)")
        line(f"- 무사: **{d['intact']}**")
        if d["damaged_after_response"]:
            line(f"- [!] 첫 대응 **이후**에 손상된 파일: **{d['damaged_after_response']}** "
                 f"(차단이 모든 쓰기를 막지 못함)")
        if d["suspicious_exts"]:
            line("- 의심 확장자: " + ", ".join(
                f"`{k or '(없음)'}`×{v}" for k, v in d["suspicious_exts"].most_common(10)))
    if d["notes"]:
        line(f"- 랜섬노트 후보 {len(d['notes'])}건:")
        for n in d["notes"][:10]:
            line(f"  - `{n}`")
    line("")

    # ── 5. 한 줄 평가 ───────────────────────────────────────────────
    line("## 5. 요약")
    line("")
    verdict = _verdict(tl, actions, damage)
    for v in verdict:
        line(f"- {v}")
    line("")

    return "\n".join(L)


def _verdict(tl, actions, damage) -> list[str]:
    out = []
    if not tl:
        return ["시그널이 없어 평가 불가 — 검체가 실행/탐지되지 않았을 수 있음(안티VM)."]
    if actions and tl.get("attack_start"):
        lat = actions[0]["timestamp"] - tl["attack_start"]
        out.append(f"공격 시작 후 약 {lat:.1f}초 만에 첫 차단 동작.")
    elif not actions:
        out.append("능동 대응이 한 번도 일어나지 않음 — 임계치 튜닝/조기 차단 필요.")
    if damage["scanned"]:
        out.append(
            f"디코이 {damage['scanned']}개 중 {damage['damaged']}개 손상 "
            f"({damage['damaged']/damage['scanned']*100:.0f}%). "
            f"이 비율이 곧 '탐지 전 피해량'.")
        if damage["damaged_after_response"]:
            out.append(
                f"차단 이후에도 {damage['damaged_after_response']}개가 추가 손상 — "
                f"커널 차단이 일부 우회됐거나 자식 프로세스가 계속 동작.")
    out.append("개선 1순위: 탐지 지연(=피해량)을 줄이는 선제 차단(canary 단일 트리거 등).")
    return out


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="RansomGuard detonate 후 성적 집계 (post-mortem)")
    ap.add_argument("--db", default="detector.db", help="signals SQLite (기본 detector.db)")
    ap.add_argument("--reports-dir", default="reports", help="인시던트 리포트 폴더")
    ap.add_argument("--watch", action="append", default=None,
                    help="피해 스캔할 watch 디렉터리(반복 가능). 기본 ./test_watch_dir")
    ap.add_argument("--since", type=float, default=None,
                    help="이 epoch 이후 시그널만 (기본: 마지막 세션 자동 분리)")
    ap.add_argument("--all", action="store_true",
                    help="세션 자동 분리 없이 DB 전체 분석")
    ap.add_argument("--out", default=None, help="마크다운 리포트 저장 경로")
    args = ap.parse_args()

    if args.watch is None:
        args.watch = ["./test_watch_dir"]

    db_path = Path(args.db)
    signals = load_signals(db_path, args.since)
    if signals and not args.all and args.since is None:
        before = len(signals)
        signals = isolate_last_session(signals)
        if len(signals) != before:
            print(f"[postmortem] 마지막 세션 {len(signals)}건만 분석 "
                  f"(전체 {before}건; --all 로 전체 분석). ")

    tl = build_timeline(signals)
    window = (tl["t0"], tl["t_end"]) if tl else None
    actions = load_actions(Path(args.reports_dir), window)
    first_action_ts = actions[0]["timestamp"] if actions else None
    damage = assess_damage([Path(w) for w in args.watch], first_action_ts)

    report = render(signals, tl, actions, damage, args)
    print(report)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"\n[postmortem] 저장됨: {args.out}")


if __name__ == "__main__":
    main()
