"""Generate diagram PNGs for the deliverables.

Outputs into docs/deliverables/images/:
  01_features.png      — 대/중/소 기능 분류 트리
  02_asis.png          — AS-IS 환경 및 한계점 다이어그램
  03_wbs.png           — WBS 작업 분해 트리
  04_process.png       — 탐지→스코어링→대응 프로세스 흐름도
"""
from __future__ import annotations
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib import font_manager

# Korean font setup
KOREAN_FONT_PATH = "/usr/share/fonts/noto-cjk/NotoSansCJK-Light.ttc"
if os.path.exists(KOREAN_FONT_PATH):
    font_manager.fontManager.addfont(KOREAN_FONT_PATH)
plt.rcParams["font.family"] = ["Noto Sans CJK JP", "Noto Sans CJK KR", "Noto Sans CJK", "NanumGothic", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

OUT = os.path.join(os.path.dirname(__file__), "images")
os.makedirs(OUT, exist_ok=True)


# ----- shared helpers -----
def box(ax, x, y, w, h, text, fc="#E8F0FE", ec="#3367D6", fontsize=9, fontweight="normal", text_color="#202124"):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                       linewidth=1.2, edgecolor=ec, facecolor=fc)
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fontsize, fontweight=fontweight, color=text_color, wrap=True)


def arrow(ax, x1, y1, x2, y2, color="#5F6368", style="-|>", lw=1.2):
    a = FancyArrowPatch((x1, y1), (x2, y2),
                        arrowstyle=style, mutation_scale=14,
                        color=color, linewidth=lw,
                        connectionstyle="arc3,rad=0")
    ax.add_patch(a)


# =============================================================
# 1. 기능 분류 트리 (대 / 중 / 소)
# =============================================================
def gen_features():
    fig, ax = plt.subplots(figsize=(20, 12))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 12)
    ax.axis("off")
    ax.set_title("RansomGuard EDR — 기능 분류 (대 / 중 / 소)",
                 fontsize=16, fontweight="bold", pad=14)

    # Root
    box(ax, 8.5, 10.8, 3, 0.7, "RansomGuard EDR",
        fc="#1A73E8", ec="#0B47A1", fontsize=12, fontweight="bold", text_color="white")

    # 대분류 (6개)
    majors = [
        ("F1\n커널 I/O 감시",       1.0, 9.2, "#FCE8E6", "#D93025"),
        ("F2\n사용자모드 탐지",    4.4, 9.2, "#FEF7E0", "#F9AB00"),
        ("F3\n스코어링/저장",      7.8, 9.2, "#E6F4EA", "#188038"),
        ("F4\n능동 대응",          11.2, 9.2, "#E8F0FE", "#1A73E8"),
        ("F5\n모니터링",           14.6, 9.2, "#F3E8FD", "#8430CE"),
        ("F6\n설치/운영",          18.0, 9.2, "#E0F7FA", "#00838F"),
    ]
    for txt, x, y, fc, ec in majors:
        box(ax, x - 0.9, y, 1.8, 0.8, txt, fc=fc, ec=ec, fontsize=10, fontweight="bold")
        arrow(ax, 10, 10.78, x, y + 0.8)

    # 중분류 (각 대분류 아래 2~4개)
    groups = {
        "F1": [("F1.1 IRP 콜백", 1.0, 8.0),
               ("F1.2 격리·차단", 1.0, 7.2),
               ("F1.3 포트 통신", 1.0, 6.4)],
        "F2": [("F2.1 Canary", 4.4, 8.0),
               ("F2.2 FS 버스트", 4.4, 7.2),
               ("F2.3 Cmdline 룰", 4.4, 6.4),
               ("F2.4 Proc 트리", 4.4, 5.6)],
        "F3": [("F3.1 Scoring", 7.8, 8.0),
               ("F3.2 EventStore", 7.8, 7.2)],
        "F4": [("F4.1 모드", 11.2, 8.0),
               ("F4.2 종료 전략", 11.2, 7.2),
               ("F4.3 변조 방지", 11.2, 6.4)],
        "F5": [("F5.1 Dashboard", 14.6, 8.0),
               ("F5.2 Incident", 14.6, 7.2),
               ("F5.3 로깅", 14.6, 6.4)],
        "F6": [("F6.1 Bootstrap", 18.0, 8.0),
               ("F6.2 Driver 빌드", 18.0, 7.2),
               ("F6.3 Service", 18.0, 6.4)],
    }
    major_xy = {m[0].split("\n")[0]: (m[1], m[2]) for m in majors}
    for key, items in groups.items():
        mx, my = major_xy[key]
        for txt, x, y in items:
            box(ax, x - 1.05, y, 2.1, 0.55, txt, fc="white", ec="#5F6368", fontsize=8.5)
            arrow(ax, mx, my, x, y + 0.55, color="#9AA0A6")

    # 소분류 (각 중분류 첫줄에 대표 예시 — 공간 절약)
    smalls = {
        "F1.1": "• Create/Write/SetInfo 콜백",
        "F1.2": "• PID 비트맵 + Write/Rename 차단",
        "F1.3": "• 50ms 송신 / Cmd 수신",
        "F2.1": "• 5종 deploy / SHA-256 폴링\n• Mass-IO 부스트 전파",
        "F2.2": "• 매직 손실 / 엔트로피 / rename\n• 수정 버스트 + fan-out",
        "F2.3": "• VSS/BCD/Defender/PS 난독화\n• 안티포렌식/지속화",
        "F2.4": "• LOLBin 체인 / fan-out / 쓰기 버스트",
        "F3.1": "• 120s 윈도우 / 4단계 임계",
        "F3.2": "• SQLite signals + 인덱스",
        "F4.1": "• OFF / QUARANTINE / KILL",
        "F4.2": "• psutil → ctypes 폴백\n• NEVER_KILL 보호",
        "F4.3": "• Process Critical / Watchdog",
        "F5.1": "• 상태/이벤트/프로세스/Kill API",
        "F5.2": "• MD 리포트 + 토스트/OS 알림",
        "F5.3": "• 콘솔 + 액션 1000건 캡",
        "F6.1": "• Python+venv+pywin32",
        "F6.2": "• MSBuild + setupapi INF",
        "F6.3": "• LocalSystem + DACL 잠금",
    }
    pos_map = {}
    for items in groups.values():
        for txt, x, y in items:
            key = txt.split()[0]
            pos_map[key] = (x, y)

    # 좌측 범례 박스로 소분류 모음
    legend_x = 0.4
    legend_y_top = 4.6
    box(ax, legend_x, 0.4, 19.2, 4.2, "", fc="#FAFAFA", ec="#DADCE0")
    ax.text(legend_x + 0.3, 4.4, "소분류 (대표 항목 — 자세한 사항은 마크다운 표 참조)",
            fontsize=10, fontweight="bold", color="#202124")

    cols = 6
    col_w = 19.2 / cols
    order = ["F1.1", "F1.2", "F1.3", "F2.1", "F2.2", "F2.3",
             "F2.4", "F3.1", "F3.2", "F4.1", "F4.2", "F4.3",
             "F5.1", "F5.2", "F5.3", "F6.1", "F6.2", "F6.3"]
    for idx, k in enumerate(order):
        col = idx % cols
        row = idx // cols
        bx = legend_x + 0.2 + col * col_w
        by = 3.7 - row * 1.15
        ax.text(bx + 0.05, by + 0.4, k, fontsize=8.5, fontweight="bold", color="#1A73E8")
        ax.text(bx + 0.05, by, smalls[k], fontsize=7.5, va="top", color="#202124")

    plt.tight_layout()
    out = os.path.join(OUT, "01_features.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


# =============================================================
# 2. AS-IS — 시스템 도입 이전 환경
# =============================================================
def gen_asis():
    fig, ax = plt.subplots(figsize=(18, 11))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 11)
    ax.axis("off")
    ax.set_title("AS-IS — RansomGuard 도입 이전 Windows 11 호스트 상태",
                 fontsize=16, fontweight="bold", pad=12)

    # User endpoint
    box(ax, 0.5, 8.5, 17, 1.7, "Windows 11 사용자 엔드포인트 (현재)",
        fc="#E8F0FE", ec="#1A73E8", fontsize=12, fontweight="bold")

    # Defenses inside endpoint
    defenses = [
        ("Windows Defender\n(시그니처 + AMSI)", 1.2, 8.7),
        ("Controlled Folder\nAccess (옵션)", 4.5, 8.7),
        ("BitLocker / EFS\n(저장 데이터 암호화)", 7.8, 8.7),
        ("표준 백업\n(파일 히스토리)", 11.1, 8.7),
        ("이벤트 로그\n(사후 분석)", 14.4, 8.7),
    ]
    for txt, x, y in defenses:
        box(ax, x, y, 2.7, 1.2, txt, fc="white", ec="#3367D6", fontsize=9)

    # Threat actors
    box(ax, 0.5, 6.0, 17, 1.7, "랜섬웨어 공격 흐름 (현재 환경에서)",
        fc="#FCE8E6", ec="#D93025", fontsize=12, fontweight="bold")

    stages = [
        ("초기 침투\n(피싱/USB)", 0.8),
        ("실행 (LOLBin\nPowerShell, mshta)", 4.0),
        ("권한 상승 +\n방어 무력화", 7.2),
        ("VSS 삭제\nbcdedit 조작", 10.4),
        ("대량 파일\n암호화", 13.6),
        ("랜섬 노트\n표시", 16.8),
    ]
    prev_x = None
    for i, (txt, x) in enumerate(stages):
        box(ax, x, 6.2, 1.0, 1.2, txt, fc="white", ec="#D93025", fontsize=8.5)
        if prev_x is not None:
            arrow(ax, prev_x + 1.0, 6.8, x, 6.8, color="#D93025", lw=1.6)
        prev_x = x

    # Gap / limitation block
    box(ax, 0.5, 2.5, 8.3, 3.0, "현재 방어의 한계 (Gap)", fc="#FEF7E0", ec="#F9AB00",
        fontsize=12, fontweight="bold")
    gaps = [
        "G1.  Defender 는 시그니처 기반 → 신종/난독화 PowerShell 미탐",
        "G2.  파일 I/O 행위(엔트로피·rename 폭주)에 대한 실시간 감지 없음",
        "G3.  VSS/BCD 등 사전 무력화 단계 차단 메커니즘 부재",
        "G4.  탐지되더라도 사후 알람만 — 진행 중 프로세스 자동 종료 X",
        "G5.  Canary/Trip-wire 같은 능동 미끼 메커니즘 없음",
        "G6.  사고 발생 시 사람이 직접 이벤트 로그 분석 (수 시간 소요)",
        "G7.  탐지 컴포넌트가 변조에 약함 — 공격자가 먼저 무력화 가능",
    ]
    for i, g in enumerate(gaps):
        ax.text(0.8, 5.0 - i * 0.32, g, fontsize=8.5, color="#5F6368", va="top")

    # Impact block
    box(ax, 9.2, 2.5, 8.3, 3.0, "결과적 피해 (Impact)", fc="#FCE8E6", ec="#D93025",
        fontsize=12, fontweight="bold")
    impacts = [
        "• 평균 탐지 지연: 수십 분 ~ 수 시간",
        "• 암호화 시작 후 사용자 데이터 전 영역 손실 위험",
        "• 백업·복원본까지 동시 손실 (섀도카피 삭제됨)",
        "• 대응 인력의 야간/주말 호출 비용",
        "• 침해 범위 식별이 어려워 IR 비용 상승",
        "• 사용자가 의심 행위를 인지할 가시화 도구 부재",
    ]
    for i, t in enumerate(impacts):
        ax.text(9.5, 5.0 - i * 0.35, t, fontsize=9, color="#202124", va="top")

    # Direction arrow at bottom
    box(ax, 3.5, 0.5, 11, 1.4,
        "→ TO-BE : 커널 minifilter + 행위 디텍터 + 능동 대응 + 가시화 대시보드 (RansomGuard EDR)",
        fc="#E6F4EA", ec="#188038", fontsize=11, fontweight="bold", text_color="#0B5C2E")

    plt.tight_layout()
    out = os.path.join(OUT, "02_asis.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


# =============================================================
# 3. WBS — Work Breakdown Structure
# =============================================================
def gen_wbs():
    fig, ax = plt.subplots(figsize=(20, 13))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 13)
    ax.axis("off")
    ax.set_title("WBS — RansomGuard EDR 프로젝트 작업 분해 구조",
                 fontsize=16, fontweight="bold", pad=12)

    # Level 0
    box(ax, 8.0, 11.8, 4, 0.8, "1.0  RansomGuard EDR 개발",
        fc="#1A73E8", ec="#0B47A1", fontsize=12, fontweight="bold", text_color="white")

    # Level 1 (phases)
    phases = [
        ("1.1 요구분석",        1.5, 10.4, "#FCE8E6", "#D93025"),
        ("1.2 아키텍처 설계",   5.0, 10.4, "#FEF7E0", "#F9AB00"),
        ("1.3 커널 드라이버",   8.5, 10.4, "#E6F4EA", "#188038"),
        ("1.4 유저모드 에이전트", 12.0, 10.4, "#E8F0FE", "#1A73E8"),
        ("1.5 통합/배포/검증",  15.5, 10.4, "#F3E8FD", "#8430CE"),
    ]
    for txt, x, y, fc, ec in phases:
        box(ax, x, y, 3.0, 0.7, txt, fc=fc, ec=ec, fontsize=10.5, fontweight="bold")
        arrow(ax, 10, 11.78, x + 1.5, y + 0.7)

    # Level 2 (work packages) — for each phase
    wbs = {
        "1.1": [
            ("1.1.1 위협 모델링", "F1·F2 도입 근거"),
            ("1.1.2 비기능 요구 정의", "응답<1s, 50ms 커널 타임아웃"),
            ("1.1.3 NEVER_KILL 정책 합의", "lsass/csrss/python 보호"),
        ],
        "1.2": [
            ("1.2.1 데이터 흐름 설계", "커널→포트→Detector→Scoring"),
            ("1.2.2 RG_EVENT 프로토콜", "RansomGuard.h v1 확정"),
            ("1.2.3 스코어링 모델", "120s 윈도우 / 4 임계"),
            ("1.2.4 SQLite 스키마", "signals 테이블 + 인덱스"),
        ],
        "1.3": [
            ("1.3.1 IRP 콜백 구현", "Create/Write/SetInfo"),
            ("1.3.2 격리 비트맵", "256슬롯 push-lock 보호"),
            ("1.3.3 통신 포트", "FltCreateCommunicationPort"),
            ("1.3.4 INF + 빌드", "build_driver.ps1 / installer"),
        ],
        "1.4": [
            ("1.4.1 minifilter_bridge", "ctypes fltlib 클라이언트"),
            ("1.4.2 Canary Detector", "5종 파일 + SHA-256 폴링"),
            ("1.4.3 Mass-IO Detector", "엔트로피 + 버스트 + fan-out"),
            ("1.4.4 Cmdline Detector", "WMI + 정규식 RULES"),
            ("1.4.5 Process Watcher", "psutil LOLBin 체인"),
            ("1.4.6 Responder", "OFF/QUARANTINE/KILL"),
            ("1.4.7 Incident Reporter", "MD + 토스트 + OS 알림"),
            ("1.4.8 Tamper 방지", "Process Critical + 핸들"),
        ],
        "1.5": [
            ("1.5.1 Flask Dashboard", "/api/* + index.html"),
            ("1.5.2 Service 설치 스크립트", "install_services.ps1"),
            ("1.5.3 Watchdog", "5s heartbeat 자동 재기동"),
            ("1.5.4 Simulator", "tests/simulator.py — 안전 검증"),
            ("1.5.5 위키 / README", "WIKI.ko.md / WIKI.en.md"),
        ],
    }
    phase_x = {p[0].split()[0]: p[1] for p in phases}
    for key, items in wbs.items():
        x0 = phase_x[key] + 1.5
        y0 = 10.0
        for i, (code, desc) in enumerate(items):
            y = y0 - 0.85 - i * 0.85
            box(ax, x0 - 1.6, y, 3.2, 0.7,
                f"{code}\n{desc}", fc="white", ec="#5F6368", fontsize=7.8)
            if i == 0:
                arrow(ax, x0, 10.4, x0, y + 0.7, color="#9AA0A6")
            else:
                arrow(ax, x0 - 1.6, y + 1.55, x0 - 1.6, y + 0.7, color="#9AA0A6")

    # Schedule bar at bottom
    box(ax, 0.5, 0.4, 19, 1.6, "", fc="#FAFAFA", ec="#DADCE0")
    ax.text(0.7, 1.8, "일정 (마일스톤)", fontsize=10, fontweight="bold")

    weeks = [
        ("M1 요구/설계", 0.7, "#FCE8E6"),
        ("M2 드라이버 PoC", 3.7, "#E6F4EA"),
        ("M3 디텍터 셋", 7.0, "#E8F0FE"),
        ("M4 대응/리포트", 10.7, "#FEF7E0"),
        ("M5 서비스화/검증", 14.2, "#F3E8FD"),
        ("M6 문서/릴리스", 17.0, "#E0F7FA"),
    ]
    for txt, x, fc in weeks:
        box(ax, x, 0.75, 2.8, 0.8, txt, fc=fc, ec="#5F6368", fontsize=9)

    plt.tight_layout()
    out = os.path.join(OUT, "03_wbs.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


# =============================================================
# 4. 프로세스 정리도 (탐지 → 스코어링 → 대응 → 보고)
# =============================================================
def gen_process():
    fig, ax = plt.subplots(figsize=(20, 12))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 12)
    ax.axis("off")
    ax.set_title("RansomGuard EDR — 프로세스 정리도 (탐지 → 스코어링 → 대응 → 보고)",
                 fontsize=16, fontweight="bold", pad=12)

    # Lane labels
    lanes = [
        ("커널 모드",       10.0, "#FCE8E6"),
        ("탐지 (Detector)", 8.0,  "#FEF7E0"),
        ("판단 (Scoring)",  6.0,  "#E8F0FE"),
        ("대응 (Responder)", 4.0, "#E6F4EA"),
        ("기록·가시화",     2.0,  "#F3E8FD"),
        ("사용자",          0.4,  "#E0F7FA"),
    ]
    for label, y, fc in lanes:
        ax.add_patch(FancyBboxPatch((0.2, y), 19.6, 1.5,
                                    boxstyle="round,pad=0.02,rounding_size=0.08",
                                    facecolor=fc, edgecolor="#DADCE0", linewidth=0.8))
        ax.text(0.4, y + 0.75, label, fontsize=10, fontweight="bold",
                color="#202124", va="center")

    # --- Kernel lane ---
    box(ax, 2.0, 10.2, 2.5, 1.0, "IRP_MJ_WRITE\nIRP_MJ_SETINFO\nIRP_MJ_CREATE",
        fc="white", ec="#D93025", fontsize=8.5)
    box(ax, 5.5, 10.2, 2.5, 1.0, "RgPostWrite /\nRgPreSetInfo\n(4KB+ throttle)",
        fc="white", ec="#D93025", fontsize=8.5)
    box(ax, 9.0, 10.2, 2.5, 1.0, "FltSendMessage\n(50ms timeout)",
        fc="white", ec="#D93025", fontsize=8.5)
    box(ax, 12.5, 10.2, 3.0, 1.0, "격리 PID 일치?\n(QuarantinedPids[256])",
        fc="white", ec="#D93025", fontsize=8.5)
    box(ax, 16.0, 10.2, 2.5, 1.0, "STATUS_ACCESS\n_DENIED 반환",
        fc="#FCE8E6", ec="#D93025", fontsize=8.5, fontweight="bold")

    arrow(ax, 4.5, 10.7, 5.5, 10.7, color="#D93025")
    arrow(ax, 8.0, 10.7, 9.0, 10.7, color="#D93025")
    arrow(ax, 11.5, 10.7, 12.5, 10.7, color="#D93025")
    arrow(ax, 15.5, 10.7, 16.0, 10.7, color="#D93025")

    # --- Detector lane ---
    detectors = [
        ("minifilter_bridge\n(write/rename burst)", 2.0),
        ("CanaryDetector\n(SHA-256 폴링)", 5.5),
        ("MassIODetector\n(엔트로피·확장자·fan-out)", 9.0),
        ("ProcessCmdlineDetector\n(WMI 정규식 RULES)", 12.5),
        ("ProcessWatcher\n(psutil LOLBin 체인)", 16.0),
    ]
    for txt, x in detectors:
        box(ax, x, 8.2, 2.7, 1.0, txt, fc="white", ec="#F9AB00", fontsize=8.5)

    # Arrows kernel -> bridge
    arrow(ax, 10.5, 10.2, 3.0, 9.2, color="#9AA0A6")

    # Detector -> Scoring
    for x in [2.0, 5.5, 9.0, 12.5, 16.0]:
        arrow(ax, x + 1.35, 8.2, 8.5 + 0.0, 7.0, color="#9AA0A6")

    # --- Scoring lane ---
    box(ax, 5.5, 6.2, 3.0, 1.0, "ScoringEngine.submit()\n슬라이딩 120s 윈도우",
        fc="white", ec="#1A73E8", fontsize=9, fontweight="bold")
    box(ax, 9.5, 6.2, 3.0, 1.0, "임계값 분류\nLOW/MED/HIGH/CRITICAL",
        fc="white", ec="#1A73E8", fontsize=9)
    box(ax, 13.5, 6.2, 3.0, 1.0, "리스너 브로드캐스트\n(_on_signal / mass_io / responder)",
        fc="white", ec="#1A73E8", fontsize=8.5)
    arrow(ax, 8.5, 6.7, 9.5, 6.7, color="#1A73E8")
    arrow(ax, 12.5, 6.7, 13.5, 6.7, color="#1A73E8")

    # --- Responder lane ---
    box(ax, 2.0, 4.2, 2.7, 1.0, "_on_signal()\nEventStore 영구 저장",
        fc="white", ec="#188038", fontsize=8.5)
    box(ax, 5.5, 4.2, 2.7, 1.0, "MassIO _on_engine_signal\n(canary boost 30s)",
        fc="white", ec="#188038", fontsize=8.5)
    box(ax, 9.0, 4.2, 3.0, 1.0, "ProcessResponder._dispatch\nPID + HIGH/CRIT?",
        fc="white", ec="#188038", fontsize=9, fontweight="bold")
    box(ax, 12.7, 4.2, 2.7, 1.0, "NEVER_KILL 검사\n(lsass/csrss/python)",
        fc="white", ec="#188038", fontsize=8.5)
    box(ax, 15.7, 4.2, 2.7, 1.0, "quarantine_pid +\nTerminateProcess",
        fc="#E6F4EA", ec="#188038", fontsize=8.5, fontweight="bold")

    arrow(ax, 15.0, 6.2, 10.5, 5.2, color="#188038")
    arrow(ax, 12.0, 4.7, 12.7, 4.7, color="#188038")
    arrow(ax, 15.4, 4.7, 15.7, 4.7, color="#188038")
    # Decision back to kernel
    arrow(ax, 17.0, 5.2, 14.0, 10.2, color="#188038", style="-|>", lw=1.6)
    ax.text(14.5, 7.7, "Quarantine\n명령", fontsize=8, color="#188038", fontweight="bold")

    # --- Reporting lane ---
    box(ax, 2.0, 2.2, 3.2, 1.0, "EventStore (SQLite)\nsignals + 인덱스",
        fc="white", ec="#8430CE", fontsize=9)
    box(ax, 6.0, 2.2, 3.2, 1.0, "IncidentReporter.on_action\nMD 리포트 생성",
        fc="white", ec="#8430CE", fontsize=9)
    box(ax, 10.0, 2.2, 3.2, 1.0, "Dashboard /api/*\n실시간 폴링 + 토스트",
        fc="white", ec="#8430CE", fontsize=9)
    box(ax, 14.0, 2.2, 4.5, 1.0, "OS 알림 (win10toast /\nBurntToast / MessageBoxW)",
        fc="white", ec="#8430CE", fontsize=9)

    arrow(ax, 3.5, 4.2, 3.5, 3.2, color="#8430CE")
    arrow(ax, 17.0, 4.2, 8.0, 3.2, color="#8430CE")
    arrow(ax, 9.2, 2.7, 10.0, 2.7, color="#8430CE")
    arrow(ax, 13.2, 2.7, 14.0, 2.7, color="#8430CE")

    # --- User lane ---
    box(ax, 6.0, 0.55, 3.5, 1.0, "관리자 — 대시보드 확인\n수동 Kill / Release",
        fc="white", ec="#00838F", fontsize=9)
    box(ax, 12.0, 0.55, 4.0, 1.0, "사용자 — 토스트/OS 알림\n인시던트 MD 확인",
        fc="white", ec="#00838F", fontsize=9)
    arrow(ax, 11.0, 2.2, 8.0, 1.55, color="#00838F")
    arrow(ax, 16.0, 2.2, 14.0, 1.55, color="#00838F")

    # Legend
    ax.text(0.4, 11.7, "흐름 색상: 빨강=커널 I/O, 노랑=탐지, 파랑=스코어링, 초록=대응, 보라=기록/가시화, 청록=사용자",
            fontsize=8, color="#5F6368")

    plt.tight_layout()
    out = os.path.join(OUT, "04_process.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    gen_features()
    gen_asis()
    gen_wbs()
    gen_process()
