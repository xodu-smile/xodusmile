"""Generate diagram PNGs for the deliverables.

Outputs into docs/deliverables/images/:
  01_features.png      — 대/중/소 기능 분류 트리
  02_asis.png          — AS-IS 환경 및 한계점 다이어그램
  03_wbs.png           — WBS 작업 분해 트리
  04_process.png       — 탐지→스코어링→대응 프로세스 흐름도
  05_ia.png            — 정보 구조 (Information Architecture)
  06_architecture.png  — 계층형 컴포넌트 아키텍처
"""
from __future__ import annotations
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
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
# zorder 규약: 밴드/섹션 배경 0.5 < 화살표·연결선 2 < 박스 3 < 텍스트 4
def box(ax, x, y, w, h, text, fc="#E8F0FE", ec="#3367D6", fontsize=9,
        fontweight="normal", text_color="#202124"):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                       linewidth=1.2, edgecolor=ec, facecolor=fc, zorder=3)
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fontsize, fontweight=fontweight, color=text_color, zorder=4)


def section(ax, x, y, w, h, label, fc, ec="#DADCE0", label_fs=10.5):
    """배경 밴드 + 좌상단 제목 (내부 박스와 겹치지 않게 상단 정렬)."""
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                                facecolor=fc, edgecolor=ec, linewidth=0.9, zorder=0.5))
    if label:
        ax.text(x + 0.25, y + h - 0.14, label, fontsize=label_fs, fontweight="bold",
                color="#202124", va="top", zorder=4)


def arrow(ax, x1, y1, x2, y2, color="#5F6368", style="-|>", lw=1.2):
    a = FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=13,
                        color=color, linewidth=lw, zorder=2)
    ax.add_patch(a)


def elbow(ax, pts, color="#5F6368", lw=1.2):
    """직각 경로 화살표 — 박스 사이 통로로만 지나가도록 좌표를 지정."""
    if len(pts) > 2:
        xs = [p[0] for p in pts[:-1]]
        ys = [p[1] for p in pts[:-1]]
        ax.plot(xs, ys, color=color, lw=lw, zorder=2, solid_capstyle="round")
    arrow(ax, pts[-2][0], pts[-2][1], pts[-1][0], pts[-1][1], color=color, lw=lw)


def bus(ax, parent_xy, children_tops, ymid, color="#9AA0A6", lw=1.1):
    """트리 분기: 부모 아래 수직선 → 수평 버스 → 각 자식으로 수직 화살표."""
    px, py = parent_xy
    ax.plot([px, px], [py, ymid], color=color, lw=lw, zorder=2)
    xs = sorted(set([c[0] for c in children_tops] + [px]))
    ax.plot([xs[0], xs[-1]], [ymid, ymid], color=color, lw=lw, zorder=2)
    for cx, cy in children_tops:
        arrow(ax, cx, ymid, cx, cy, color=color, lw=lw)


# =============================================================
# 1. 기능 분류 트리 (대 / 중 / 소)
# =============================================================
def gen_features():
    fig, ax = plt.subplots(figsize=(20, 12.5))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 12.5)
    ax.axis("off")
    ax.set_title("RansomGuard EDR — 기능 분류 (대 / 중 / 소)",
                 fontsize=16, fontweight="bold", pad=14)

    # Root
    box(ax, 8.6, 11.3, 2.8, 0.7, "RansomGuard EDR",
        fc="#1A73E8", ec="#0B47A1", fontsize=12, fontweight="bold", text_color="white")

    centers = [2.0, 5.2, 8.4, 11.6, 14.8, 18.0]
    majors = [
        ("F1\n커널 I/O 감시",   "#FCE8E6", "#D93025"),
        ("F2\n사용자모드 탐지", "#FEF7E0", "#F9AB00"),
        ("F3\n스코어링/저장",   "#E6F4EA", "#188038"),
        ("F4\n능동 대응",       "#E8F0FE", "#1A73E8"),
        ("F5\n모니터링",        "#F3E8FD", "#8430CE"),
        ("F6\n설치/운영",       "#E0F7FA", "#00838F"),
    ]
    for c, (txt, fc, ec) in zip(centers, majors):
        box(ax, c - 1.3, 9.9, 2.6, 0.8, txt, fc=fc, ec=ec, fontsize=10, fontweight="bold")
    bus(ax, (10, 11.3), [(c, 10.7) for c in centers], ymid=11.0)

    # 중분류 — 각 대분류 바로 아래 수직 체인
    groups = [
        ["F1.1 IRP 콜백", "F1.2 격리·차단", "F1.3 포트 통신"],
        ["F2.1 Canary", "F2.2 FS 버스트", "F2.3 Cmdline 룰", "F2.4 Proc 트리"],
        ["F3.1 Scoring", "F3.2 EventStore"],
        ["F4.1 대응 모드", "F4.2 종료 전략", "F4.3 변조 방지"],
        ["F5.1 Dashboard", "F5.2 Incident", "F5.3 로깅"],
        ["F6.1 Bootstrap", "F6.2 Driver 빌드", "F6.3 Service"],
    ]
    for c, items in zip(centers, groups):
        prev_bottom = 9.9
        for i, txt in enumerate(items):
            y = 8.85 - i * 0.85
            box(ax, c - 1.3, y, 2.6, 0.6, txt, fc="white", ec="#5F6368", fontsize=9)
            arrow(ax, c, prev_bottom, c, y + 0.6, color="#9AA0A6")
            prev_bottom = y

    # 소분류 — 가족별 세로 컬럼 (대분류와 같은 열에 정렬)
    smalls = [
        [("F1.1", "• Create/Write/SetInfo 콜백"),
         ("F1.2", "• PID 비트맵[256]\n• Write/Rename 차단"),
         ("F1.3", "• 50ms 송신 / Cmd 수신")],
        [("F2.1", "• 5종 deploy / SHA-256 폴링\n• Mass-IO 부스트 전파"),
         ("F2.2", "• 매직 손실 / 엔트로피 / rename\n• 수정 버스트 + fan-out"),
         ("F2.3", "• VSS/BCD/Defender 무력화\n• PS 난독화 / 안티포렌식"),
         ("F2.4", "• LOLBin 체인 / fan-out")],
        [("F3.1", "• 120s 윈도우 / 4단계 임계"),
         ("F3.2", "• SQLite signals + 인덱스")],
        [("F4.1", "• OFF / QUARANTINE / KILL"),
         ("F4.2", "• psutil → ctypes 폴백\n• NEVER_KILL 보호"),
         ("F4.3", "• Process Critical / Watchdog")],
        [("F5.1", "• 상태/이벤트/프로세스 API\n• 수동 Kill / Release"),
         ("F5.2", "• MD 리포트 + 토스트 알림"),
         ("F5.3", "• 콘솔 + 액션 1000건 캡")],
        [("F6.1", "• Python+venv+pywin32"),
         ("F6.2", "• MSBuild + setupapi INF"),
         ("F6.3", "• LocalSystem + DACL 잠금")],
    ]
    section(ax, 0.4, 0.4, 19.2, 5.3,
            "소분류 (대표 항목 — 자세한 사항은 마크다운 표 참조)", "#FAFAFA")
    for c, items in zip(centers, smalls):
        x = c - 1.45
        y = 4.95
        for key, txt in items:
            nlines = txt.count("\n") + 1
            ax.text(x, y, key, fontsize=8.5, fontweight="bold",
                    color="#1A73E8", va="top", zorder=4)
            ax.text(x, y - 0.32, txt, fontsize=7.5, va="top", color="#202124", zorder=4)
            y -= 0.34 + 0.30 * nlines + 0.20

    out = os.path.join(OUT, "01_features.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


# =============================================================
# 2. AS-IS — 시스템 도입 이전 환경
# =============================================================
def gen_asis():
    fig, ax = plt.subplots(figsize=(18, 11.5))
    ax.set_xlim(0, 18)
    ax.set_ylim(0, 11.5)
    ax.axis("off")
    ax.set_title("AS-IS — RansomGuard 도입 이전 Windows 11 호스트 상태",
                 fontsize=16, fontweight="bold", pad=12)

    # 기존 방어 수단
    section(ax, 0.5, 8.4, 17, 2.3, "Windows 11 사용자 엔드포인트 — 기존 방어 수단",
            "#E8F0FE", ec="#1A73E8", label_fs=12)
    defenses = [
        "Windows Defender\n(시그니처 + AMSI)",
        "Controlled Folder\nAccess (옵션)",
        "BitLocker / EFS\n(저장 데이터 암호화)",
        "표준 백업\n(파일 히스토리)",
        "이벤트 로그\n(사후 분석)",
    ]
    for i, txt in enumerate(defenses):
        box(ax, 0.9 + i * 3.26, 8.65, 2.9, 1.25, txt, fc="white", ec="#3367D6", fontsize=9)

    # 공격 흐름
    section(ax, 0.5, 5.6, 17, 2.4, "랜섬웨어 공격 흐름 (현재 환경 — 차단 지점 없음)",
            "#FCE8E6", ec="#D93025", label_fs=12)
    stages = [
        "초기 침투\n(피싱 / USB)",
        "실행\n(LOLBin·mshta)",
        "권한 상승 +\n방어 무력화",
        "VSS 삭제\nbcdedit 조작",
        "대량 파일\n암호화",
        "랜섬 노트\n표시",
    ]
    for i, txt in enumerate(stages):
        x = 0.9 + i * 2.72
        box(ax, x, 5.85, 2.3, 1.25, txt, fc="white", ec="#D93025", fontsize=9)
        if i > 0:
            arrow(ax, x - 0.42, 6.47, x, 6.47, color="#D93025", lw=1.6)

    # Gap / Impact
    ax.add_patch(FancyBboxPatch((0.5, 1.95), 8.3, 3.2,
                                boxstyle="round,pad=0.02,rounding_size=0.06",
                                facecolor="#FEF7E0", edgecolor="#F9AB00",
                                linewidth=1.2, zorder=0.5))
    ax.text(4.65, 4.88, "현재 방어의 한계 (Gap)", fontsize=11.5, fontweight="bold",
            ha="center", va="top", zorder=4)
    gaps = [
        "G1.  Defender 는 시그니처 기반 → 신종/난독화 PowerShell 미탐",
        "G2.  파일 I/O 행위(엔트로피·rename 폭주) 실시간 감지 없음",
        "G3.  VSS/BCD 등 사전 무력화 단계 차단 메커니즘 부재",
        "G4.  탐지되더라도 사후 알람만 — 진행 중 프로세스 자동 종료 X",
        "G5.  Canary/Trip-wire 같은 능동 미끼 메커니즘 없음",
        "G6.  사고 발생 시 사람이 직접 이벤트 로그 분석 (수 시간 소요)",
        "G7.  탐지 컴포넌트가 변조에 약함 — 공격자가 먼저 무력화 가능",
    ]
    for i, g in enumerate(gaps):
        ax.text(0.85, 4.42 - i * 0.36, g, fontsize=8.6, color="#5F6368", va="top", zorder=4)

    ax.add_patch(FancyBboxPatch((9.2, 1.95), 8.3, 3.2,
                                boxstyle="round,pad=0.02,rounding_size=0.06",
                                facecolor="#FCE8E6", edgecolor="#D93025",
                                linewidth=1.2, zorder=0.5))
    ax.text(13.35, 4.88, "결과적 피해 (Impact)", fontsize=11.5, fontweight="bold",
            ha="center", va="top", zorder=4)
    impacts = [
        "• 평균 탐지 지연: 수십 분 ~ 수 시간",
        "• 암호화 시작 후 사용자 데이터 전 영역 손실 위험",
        "• 백업·복원본까지 동시 손실 (섀도카피 삭제됨)",
        "• 대응 인력의 야간/주말 호출 비용",
        "• 침해 범위 식별이 어려워 IR 비용 상승",
        "• 사용자가 의심 행위를 인지할 가시화 도구 부재",
    ]
    for i, t in enumerate(impacts):
        ax.text(9.55, 4.42 - i * 0.4, t, fontsize=9, color="#202124", va="top", zorder=4)

    arrow(ax, 4.65, 5.6, 4.65, 5.15, color="#9AA0A6")
    arrow(ax, 13.35, 5.6, 13.35, 5.15, color="#9AA0A6")

    # TO-BE
    box(ax, 3.0, 0.45, 12, 1.0,
        "→ TO-BE : 커널 minifilter + 행위 디텍터 + 능동 대응 + 가시화 대시보드 (RansomGuard EDR)",
        fc="#E6F4EA", ec="#188038", fontsize=11, fontweight="bold", text_color="#0B5C2E")
    arrow(ax, 4.65, 1.95, 4.65, 1.45, color="#188038")
    arrow(ax, 13.35, 1.95, 13.35, 1.45, color="#188038")

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

    box(ax, 8.0, 12.0, 4.0, 0.8, "1.0  RansomGuard EDR 개발",
        fc="#1A73E8", ec="#0B47A1", fontsize=12, fontweight="bold", text_color="white")

    centers = [2.4, 6.2, 10.0, 13.8, 17.6]
    phases = [
        ("1.1 요구분석",          "#FCE8E6", "#D93025"),
        ("1.2 아키텍처 설계",     "#FEF7E0", "#F9AB00"),
        ("1.3 커널 드라이버",     "#E6F4EA", "#188038"),
        ("1.4 유저모드 에이전트", "#E8F0FE", "#1A73E8"),
        ("1.5 통합/배포/검증",    "#F3E8FD", "#8430CE"),
    ]
    for c, (txt, fc, ec) in zip(centers, phases):
        box(ax, c - 1.6, 10.7, 3.2, 0.7, txt, fc=fc, ec=ec, fontsize=10.5, fontweight="bold")
    bus(ax, (10, 12.0), [(c, 11.4) for c in centers], ymid=11.7)

    wbs = [
        [("1.1.1 위협 모델링", "F1·F2 도입 근거"),
         ("1.1.2 비기능 요구 정의", "응답<1s, 50ms 커널 타임아웃"),
         ("1.1.3 NEVER_KILL 정책 합의", "lsass/csrss/python 보호")],
        [("1.2.1 데이터 흐름 설계", "커널→포트→Detector→Scoring"),
         ("1.2.2 RG_EVENT 프로토콜", "RansomGuard.h v1 확정"),
         ("1.2.3 스코어링 모델", "120s 윈도우 / 4 임계"),
         ("1.2.4 SQLite 스키마", "signals 테이블 + 인덱스")],
        [("1.3.1 IRP 콜백 구현", "Create/Write/SetInfo"),
         ("1.3.2 격리 비트맵", "256슬롯 push-lock 보호"),
         ("1.3.3 통신 포트", "FltCreateCommunicationPort"),
         ("1.3.4 INF + 빌드", "build_driver.ps1 / installer")],
        [("1.4.1 minifilter_bridge", "ctypes fltlib 클라이언트"),
         ("1.4.2 Canary Detector", "5종 파일 + SHA-256 폴링"),
         ("1.4.3 Mass-IO Detector", "엔트로피 + 버스트 + fan-out"),
         ("1.4.4 Cmdline Detector", "WMI + 정규식 RULES"),
         ("1.4.5 Process Watcher", "psutil LOLBin 체인"),
         ("1.4.6 Responder", "OFF/QUARANTINE/KILL"),
         ("1.4.7 Incident Reporter", "MD + 토스트 + OS 알림"),
         ("1.4.8 Tamper 방지", "Process Critical + 핸들")],
        [("1.5.1 Flask Dashboard", "/api/* + index.html"),
         ("1.5.2 Service 설치 스크립트", "install_services.ps1"),
         ("1.5.3 Watchdog", "5s heartbeat 자동 재기동"),
         ("1.5.4 Simulator", "tests/simulator.py — 안전 검증"),
         ("1.5.5 위키 / README", "WIKI.ko.md / WIKI.en.md")],
    ]
    for c, items in zip(centers, wbs):
        prev_bottom = 10.7
        for i, (code, desc) in enumerate(items):
            y = 9.65 - i * 0.97
            box(ax, c - 1.7, y, 3.4, 0.78, f"{code}\n{desc}",
                fc="white", ec="#5F6368", fontsize=8)
            arrow(ax, c, prev_bottom, c, y + 0.78, color="#9AA0A6")
            prev_bottom = y

    # 일정 (마일스톤)
    section(ax, 0.5, 0.4, 19, 1.8, "일정 (마일스톤)", "#FAFAFA")
    weeks = [
        ("M1 요구/설계", "#FCE8E6"),
        ("M2 드라이버 PoC", "#E6F4EA"),
        ("M3 디텍터 셋", "#E8F0FE"),
        ("M4 대응/리포트", "#FEF7E0"),
        ("M5 서비스화/검증", "#F3E8FD"),
        ("M6 문서/릴리스", "#E0F7FA"),
    ]
    for i, (txt, fc) in enumerate(weeks):
        x = 0.8 + i * 3.1
        box(ax, x, 0.65, 2.9, 0.85, txt, fc=fc, ec="#5F6368", fontsize=9.5)
        if i > 0:
            arrow(ax, x - 0.2, 1.075, x, 1.075, color="#9AA0A6")

    out = os.path.join(OUT, "03_wbs.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


# =============================================================
# 4. 프로세스 정리도 (탐지 → 스코어링 → 대응 → 보고)
# =============================================================
def gen_process():
    fig, ax = plt.subplots(figsize=(20, 11.5))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 11.5)
    ax.axis("off")
    ax.set_title("RansomGuard EDR — 프로세스 정리도 (탐지 → 스코어링 → 대응 → 보고)",
                 fontsize=16, fontweight="bold", pad=12)

    ax.text(0.2, 11.0, "레인 색상:  빨강=커널 I/O · 노랑=탐지 · 파랑=스코어링 · 초록=대응 · 보라=기록/가시화 · 청록=사용자",
            fontsize=8.5, color="#5F6368", zorder=4)

    # 스윔레인 (왼쪽 라벨 영역 x<2.0, 콘텐츠 x>=2.2)
    lanes = [
        ("커널 모드",          9.20, "#FCE8E6"),
        ("탐지\n(Detector)",   7.44, "#FEF7E0"),
        ("판단\n(Scoring)",    5.68, "#E8F0FE"),
        ("대응\n(Responder)",  3.92, "#E6F4EA"),
        ("기록·가시화",        2.16, "#F3E8FD"),
        ("사용자",             0.40, "#E0F7FA"),
    ]
    for label, y, fc in lanes:
        ax.add_patch(FancyBboxPatch((0.2, y), 19.6, 1.6,
                                    boxstyle="round,pad=0.02,rounding_size=0.08",
                                    facecolor=fc, edgecolor="#DADCE0",
                                    linewidth=0.8, zorder=0.5))
        ax.text(0.4, y + 0.8, label, fontsize=9.5, fontweight="bold",
                color="#202124", va="center", zorder=4)

    kx = [2.2, 5.65, 9.1, 12.55, 16.0]   # 체인 박스 x (w=2.9, 간격 0.55)

    # --- 커널 레인 (y 9.5~10.5) ---
    kernel = [
        "IRP_MJ_WRITE\nIRP_MJ_SETINFO\nIRP_MJ_CREATE",
        "RgPostWrite /\nRgPreSetInfo\n(4KB+ throttle)",
        "FltSendMessage\n(50ms timeout)",
        "격리 PID 일치?\nQuarantinedPids[256]",
        "STATUS_ACCESS\n_DENIED 반환",
    ]
    for x, txt in zip(kx, kernel):
        last = txt.startswith("STATUS")
        box(ax, x, 9.5, 2.9, 1.0, txt, fc="#FCE8E6" if last else "white",
            ec="#D93025", fontsize=8.5, fontweight="bold" if last else "normal")
    for x in kx[:-1]:
        arrow(ax, x + 2.9, 10.0, x + 3.45, 10.0, color="#D93025", lw=1.5)

    # --- 탐지 레인 (y 7.74~8.74) ---
    detectors = [
        "minifilter_bridge\n(write/rename burst)",
        "CanaryDetector\n(SHA-256 폴링)",
        "MassIODetector\n(엔트로피·fan-out)",
        "ProcessCmdline\n(WMI 정규식 RULES)",
        "ProcessWatcher\n(psutil LOLBin 체인)",
    ]
    for x, txt in zip(kx, detectors):
        box(ax, x, 7.74, 2.9, 1.0, txt, fc="white", ec="#F9AB00", fontsize=8.5)

    # 커널(FltSendMessage) → bridge : 레인 사이 통로(y 9.12)로 우회
    elbow(ax, [(10.55, 9.5), (10.55, 9.12), (3.65, 9.12), (3.65, 8.74)], color="#D93025")
    ax.text(6.6, 9.30, "RG_EVENT (50ms)", fontsize=7.5, color="#D93025", zorder=4)

    # --- 판단 레인 (y 5.98~6.98) ---
    box(ax, 4.5, 5.98, 3.2, 1.0, "ScoringEngine.submit()\n슬라이딩 120s 윈도우",
        fc="white", ec="#1A73E8", fontsize=9, fontweight="bold")
    box(ax, 8.7, 5.98, 3.2, 1.0, "임계값 분류\nLOW/MED/HIGH/CRITICAL",
        fc="white", ec="#1A73E8", fontsize=9)
    box(ax, 12.9, 5.98, 3.4, 1.0, "리스너 브로드캐스트\n_on_signal / mass_io / responder",
        fc="white", ec="#1A73E8", fontsize=8.3)
    arrow(ax, 7.7, 6.48, 8.7, 6.48, color="#1A73E8", lw=1.5)
    arrow(ax, 11.9, 6.48, 12.9, 6.48, color="#1A73E8", lw=1.5)

    # 탐지 → 스코어링 : 수집 버스 (레인 사이 y 7.36)
    cxs = [x + 1.45 for x in kx]
    for cx in cxs:
        ax.plot([cx, cx], [7.74, 7.36], color="#9AA0A6", lw=1.1, zorder=2)
    ax.plot([min(cxs), max(cxs)], [7.36, 7.36], color="#9AA0A6", lw=1.1, zorder=2)
    arrow(ax, 6.1, 7.36, 6.1, 6.98, color="#9AA0A6")

    # --- 대응 레인 (y 4.22~5.22) ---
    box(ax, 2.2, 4.22, 2.9, 1.0, "_on_signal()\nEventStore 영구 저장",
        fc="white", ec="#188038", fontsize=8.5)
    box(ax, 5.5, 4.22, 2.9, 1.0, "MassIO 부스트\n(canary boost 30s)",
        fc="white", ec="#188038", fontsize=8.5)
    box(ax, 8.8, 4.22, 3.2, 1.0, "ProcessResponder._dispatch\nPID + HIGH/CRIT?",
        fc="white", ec="#188038", fontsize=8.8, fontweight="bold")
    box(ax, 12.4, 4.22, 2.9, 1.0, "NEVER_KILL 검사\n(lsass/csrss/python)",
        fc="white", ec="#188038", fontsize=8.5)
    box(ax, 15.7, 4.22, 3.0, 1.0, "quarantine_pid +\nTerminateProcess",
        fc="#E6F4EA", ec="#188038", fontsize=8.5, fontweight="bold")
    arrow(ax, 12.0, 4.72, 12.4, 4.72, color="#188038", lw=1.5)
    arrow(ax, 15.3, 4.72, 15.7, 4.72, color="#188038", lw=1.5)

    # 브로드캐스트 → 대응 리스너 3개 (레인 사이 y 5.6)
    for cx in [3.65, 6.95, 10.4]:
        elbow(ax, [(14.6, 5.98), (14.6, 5.6), (cx, 5.6), (cx, 5.22)], color="#188038")

    # 격리 명령 → 커널 (우측 가장자리 통로 x 19.35)
    elbow(ax, [(18.7, 4.72), (19.35, 4.72), (19.35, 9.3), (14.0, 9.3), (14.0, 9.5)],
          color="#188038", lw=1.5)
    ax.text(19.5, 6.6, "Quarantine 명령", fontsize=7.5, color="#188038",
            rotation=90, va="center", zorder=4)

    # --- 기록·가시화 레인 (y 2.46~3.46) ---
    box(ax, 2.2, 2.46, 3.2, 1.0, "EventStore (SQLite)\nsignals + 인덱스",
        fc="white", ec="#8430CE", fontsize=9)
    box(ax, 6.2, 2.46, 3.2, 1.0, "IncidentReporter\nMD 리포트 생성",
        fc="white", ec="#8430CE", fontsize=9)
    box(ax, 10.2, 2.46, 3.2, 1.0, "Dashboard /api/*\n실시간 폴링 + 토스트",
        fc="white", ec="#8430CE", fontsize=9)
    box(ax, 14.2, 2.46, 4.4, 1.0, "OS 알림\nwin10toast / BurntToast / MessageBoxW",
        fc="white", ec="#8430CE", fontsize=8.5)

    arrow(ax, 3.65, 4.22, 3.65, 3.46, color="#8430CE")                     # _on_signal → EventStore
    elbow(ax, [(17.2, 4.22), (17.2, 3.84), (7.8, 3.84), (7.8, 3.46)],     # kill → Reporter
          color="#8430CE")
    elbow(ax, [(3.8, 3.46), (3.8, 3.62), (11.8, 3.62), (11.8, 3.46)],     # EventStore → Dashboard
          color="#8430CE")
    elbow(ax, [(8.9, 2.46), (8.9, 2.30), (16.4, 2.30), (16.4, 2.46)],     # Reporter → OS 알림
          color="#8430CE")

    # --- 사용자 레인 (y 0.7~1.7) ---
    box(ax, 6.0, 0.7, 3.6, 1.0, "관리자 — 대시보드 확인\n수동 Kill / Release",
        fc="white", ec="#00838F", fontsize=9)
    box(ax, 12.0, 0.7, 4.0, 1.0, "사용자 — 토스트/OS 알림\n인시던트 MD 확인",
        fc="white", ec="#00838F", fontsize=9)
    elbow(ax, [(11.0, 2.46), (11.0, 2.08), (7.8, 2.08), (7.8, 1.7)], color="#00838F")
    elbow(ax, [(15.2, 2.46), (15.2, 2.08), (14.0, 2.08), (14.0, 1.7)], color="#00838F")

    out = os.path.join(OUT, "04_process.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


# =============================================================
# 5. IA — 정보 구조 (Information Architecture)
# =============================================================
def gen_ia():
    fig, ax = plt.subplots(figsize=(20, 13))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 13)
    ax.axis("off")
    ax.set_title("RansomGuard EDR — 정보 구조 (Information Architecture)",
                 fontsize=16, fontweight="bold", pad=14)

    box(ax, 8.3, 12.0, 3.4, 0.85, "RansomGuard EDR\n정보 체계",
        fc="#1A73E8", ec="#0B47A1", fontsize=11.5, fontweight="bold", text_color="white")

    areas = [
        ("A. 대시보드 (Web UI)\nhttp://127.0.0.1:5000", "#E8F0FE", "#1A73E8"),
        ("B. API / 인터페이스\n/api/* · 커널 포트",     "#FEF7E0", "#F9AB00"),
        ("C. 데이터 엔티티\nSignal · Action · Incident", "#E6F4EA", "#188038"),
        ("D. 산출물 / 저장소\nDB · 리포트 · 문서",       "#F3E8FD", "#8430CE"),
    ]
    xs = [0.5 + i * 4.95 for i in range(4)]
    w = 4.35
    for x, (txt, fc, ec) in zip(xs, areas):
        box(ax, x, 10.55, w, 0.95, txt, fc=fc, ec=ec, fontsize=9.5, fontweight="bold")
    bus(ax, (10, 12.0), [(x + w / 2, 11.5) for x in xs], ymid=11.75)

    columns = [
        (["A1  위협 점수 게이지 (0~300+)",
          "A2  심각도 배지 INFO~CRITICAL",
          "A3  최근 시그널 테이블",
          "A4  프로세스 스냅샷 목록",
          "A5  리스폰더 액션 로그",
          "A6  인시던트 리포트 뷰어",
          "A7  수동 Kill / Release 컨트롤",
          "A8  토스트 알림 영역"], "#1A73E8", 8.3),
        (["GET  /api/status — 점수·레벨·통계",
          "GET  /api/events — 최근 100 시그널",
          "GET  /api/processes — psutil 스냅샷",
          "GET  /api/actions — 대응 이력",
          "GET  /api/reports[/<file>] — 리포트",
          "GET  /api/heartbeat — 생존 신호",
          "POST /api/kill · /api/release",
          "POST /api/reset — 윈도우 초기화",
          "포트 \\RansomGuardPort (RG_EVENT/CMD)",
          "WMI  Win32_Process 구독"], "#F9AB00", 7.9),
        (["Signal {detector, name, weight,\nseverity, message, meta, ts}",
          "Score {value, level, window=120s}",
          "KillAction {pid, name, mode, reason}",
          "Incident {ts, pid, timeline, action}",
          "Process {pid, name, cpu, mem, io}",
          "QuarantinePid[256] / ProtectedPid[16]",
          "ActorTrust {FULL/REG_ONLY/UNTRUSTED}",
          "Rule {pattern, weight, severity}"], "#188038", 7.9),
        (["detector.db  (SQLite signals)",
          "reports/incident_*.md",
          "canary 5종 (watch 디렉터리)",
          ".lab.json  (랩 설정)",
          "docs/deliverables/*.md + images/",
          "docs/WIKI.ko.md · WIKI.en.md",
          "README.md · README.en.md",
          "콘솔 로그 · 액션 이력 (1000 cap)"], "#8430CE", 8.1),
    ]
    for x, (items, ec, fs) in zip(xs, columns):
        cx = x + w / 2
        arrow(ax, cx, 10.55, cx, 10.18, color="#9AA0A6")
        y_top = 10.18
        for t in items:
            nlines = t.count("\n") + 1
            h = 0.5 if nlines == 1 else 0.78
            box(ax, x, y_top - h, w, h, t, fc="white", ec=ec, fontsize=fs)
            y_top -= h + 0.13

    box(ax, 0.5, 0.5, 19, 1.6,
        "탐색 흐름:  탐지기 → Signal 생성 → ScoringEngine 누적 → (A 대시보드 폴링 / C 엔티티 갱신 / D DB·리포트 영구화)\n"
        "권한:  대시보드는 localhost 전용(무인증) · 산출물 디렉터리는 DACL 로 SYSTEM/Admins 만 접근",
        fc="#FAFAFA", ec="#DADCE0", fontsize=9.5)

    out = os.path.join(OUT, "05_ia.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


# =============================================================
# 6. 아키텍처 — 계층형 컴포넌트 / 배포 구조
# =============================================================
def gen_architecture():
    fig, ax = plt.subplots(figsize=(20, 14))
    ax.set_xlim(0, 20)
    ax.set_ylim(0, 13.6)
    ax.axis("off")
    ax.set_title("RansomGuard EDR — 프로젝트 아키텍처 (계층 / 컴포넌트)",
                 fontsize=16, fontweight="bold", pad=12)

    ax.text(0.3, 13.12,
            "데이터 흐름:  커널 콜백 → MinifilterBridge → 탐지기 Signal → ScoringEngine 누적 → Responder(격리/종료) → EventStore/Reporter → 대시보드/사용자",
            fontsize=8.5, color="#5F6368", zorder=4)

    # --- 운영/사용자 (y 11.3~12.9) ---
    section(ax, 0.3, 11.3, 19.4, 1.6, "운영 / 사용자 계층", "#E0F7FA")
    box(ax, 1.5, 11.45, 3.6, 0.95, "관리자\n대시보드 · 수동 대응", fc="white", ec="#00838F", fontsize=9)
    box(ax, 6.7, 11.45, 3.6, 0.95, "사용자\nOS 토스트 알림", fc="white", ec="#00838F", fontsize=9)
    box(ax, 11.9, 11.45, 4.6, 0.95, "PowerShell 운영 스크립트\nbootstrap / install / lab.ps1",
        fc="white", ec="#00838F", fontsize=8.7)

    # --- 가시화·보고 (y 9.25~11.05) ---
    section(ax, 0.3, 9.25, 19.4, 1.8, "가시화 · 보고 계층 (User Mode)", "#F3E8FD")
    box(ax, 1.5, 9.45, 4.2, 1.1, "Flask Dashboard\ndashboard/app.py (/api/*)",
        fc="white", ec="#8430CE", fontsize=9)
    box(ax, 6.7, 9.45, 4.2, 1.1, "IncidentReporter\nincident_report.py (MD+알림)",
        fc="white", ec="#8430CE", fontsize=8.8)
    box(ax, 11.9, 9.45, 4.2, 1.1, "EventStore\nevent_store.py (SQLite)",
        fc="white", ec="#8430CE", fontsize=9)

    # --- 판단·대응 (y 7.0~9.0) ---
    section(ax, 0.3, 7.0, 19.4, 2.0, "판단 · 대응 계층 (User Mode)", "#E6F4EA")
    box(ax, 1.5, 7.2, 4.2, 1.25, "ScoringEngine\nscoring.py\n120s 윈도우 · 4단계 임계",
        fc="white", ec="#188038", fontsize=8.8, fontweight="bold")
    box(ax, 6.7, 7.2, 4.2, 1.25, "ProcessResponder\nresponder.py\nOFF/QUARANTINE/KILL",
        fc="white", ec="#188038", fontsize=8.8, fontweight="bold")
    box(ax, 11.9, 7.2, 3.2, 1.25, "actor_trust.py\n신뢰 분류", fc="white", ec="#188038", fontsize=8.7)
    box(ax, 15.6, 7.2, 3.1, 1.25, "tamper.py\n자가방어", fc="white", ec="#188038", fontsize=8.7)

    # --- 탐지 (y 4.4~6.75) ---
    section(ax, 0.3, 4.4, 19.4, 2.35, "탐지 계층 (Detectors / User Mode)", "#FEF7E0")
    dets = [
        "CanaryDetector\ncanary.py",
        "MassIODetector\nmass_io.py",
        "ProcessCmdline\nprocess_cmdline.py",
        "ProcessWatcher\nprocess_watcher.py",
        "Process/Registry\nKernel detectors",
        "MinifilterBridge\nminifilter_bridge.py",
    ]
    dxs = [1.0 + i * 3.05 for i in range(6)]
    for x, txt in zip(dxs, dets):
        box(ax, x, 4.6, 2.85, 1.4, txt, fc="white", ec="#F9AB00", fontsize=8.3)

    # --- 커널 (y 1.95~4.15) ---
    section(ax, 0.3, 1.95, 19.4, 2.2, "커널 계층 (Kernel Mode Driver)", "#FCE8E6")
    box(ax, 1.5, 2.15, 4.6, 1.4,
        "RansomGuard.sys\nminifilter/RansomGuard.c\nIRP Create/Write/SetInfo 콜백",
        fc="white", ec="#D93025", fontsize=8.5, fontweight="bold")
    box(ax, 6.9, 2.15, 4.6, 1.4,
        "프로세스/레지스트리/핸들 콜백\nPsSet.. / CmRegister.. / ObRegister..",
        fc="white", ec="#D93025", fontsize=8.3)
    box(ax, 12.3, 2.15, 4.6, 1.4,
        "격리 PID 비트맵[256]\nWrite/Rename 차단\nSTATUS_ACCESS_DENIED",
        fc="white", ec="#D93025", fontsize=8.3, fontweight="bold")

    # --- 플랫폼 (y 0.4~1.7) ---
    section(ax, 0.3, 0.4, 19.4, 1.3, "플랫폼", "#ECEFF1")
    box(ax, 2.0, 0.55, 6.0, 0.75, "Windows 11 (22H2+) x64 / ARM64 · NTFS 파일시스템",
        fc="white", ec="#607D8B", fontsize=9)
    box(ax, 9.0, 0.55, 4.0, 0.75, "Filter Manager (FltMgr)", fc="white", ec="#607D8B", fontsize=9)
    box(ax, 13.5, 0.55, 4.3, 0.75, "Python 3.10+ · pywin32 · psutil",
        fc="white", ec="#607D8B", fontsize=8.8)

    # ===== 데이터 흐름 화살표 (박스 사이 통로로만 통과) =====
    # 커널 → MinifilterBridge (RG_EVENT)
    elbow(ax, [(14.6, 3.55), (14.6, 4.28), (17.6, 4.28), (17.6, 4.6)], color="#D93025", lw=1.5)
    ax.text(14.75, 3.83, "RG_EVENT", fontsize=7.5, color="#D93025", zorder=4)

    # 탐지기 → ScoringEngine : 수집 버스 (탐지 밴드 상단 y 6.35)
    dcs = [x + 1.425 for x in dxs]
    for cx in dcs:
        ax.plot([cx, cx], [6.0, 6.35], color="#9AA0A6", lw=1.0, zorder=2)
    ax.plot([min(dcs), max(dcs)], [6.35, 6.35], color="#9AA0A6", lw=1.0, zorder=2)
    arrow(ax, 3.6, 6.35, 3.6, 7.2, color="#9AA0A6", lw=1.3)
    ax.text(3.78, 6.62, "Signal(weight)", fontsize=7.5, color="#5F6368", zorder=4)

    # ScoringEngine → Responder
    arrow(ax, 5.7, 7.82, 6.7, 7.82, color="#188038", lw=1.6)
    ax.text(6.2, 8.02, "score/level", fontsize=7.5, color="#188038", ha="center", zorder=4)

    # Responder → IncidentReporter / EventStore
    arrow(ax, 8.8, 8.45, 8.8, 9.45, color="#188038", lw=1.3)
    elbow(ax, [(9.9, 8.45), (9.9, 9.1), (14.0, 9.1), (14.0, 9.45)], color="#188038", lw=1.3)

    # Responder → 커널 (격리/종료 명령) : 탐지 박스 사이 통로 x 10.05
    elbow(ax, [(8.3, 7.2), (8.3, 6.88), (10.05, 6.88), (10.05, 3.55)], color="#188038", lw=1.5)
    ax.text(10.25, 3.8, "Quarantine / Kill 명령", fontsize=7.5, color="#188038", zorder=4)

    # EventStore → Dashboard (폴링), Dashboard → 관리자, Reporter → 사용자
    elbow(ax, [(14.0, 10.55), (14.0, 10.85), (3.9, 10.85), (3.9, 10.55)], color="#8430CE", lw=1.2)
    arrow(ax, 3.3, 10.55, 3.3, 11.45, color="#8430CE", lw=1.2)
    arrow(ax, 8.6, 10.55, 8.6, 11.45, color="#8430CE", lw=1.2)

    out = os.path.join(OUT, "06_architecture.png")
    plt.savefig(out, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out)


if __name__ == "__main__":
    gen_features()
    gen_asis()
    gen_wbs()
    gen_process()
    gen_ia()
    gen_architecture()
