# -*- coding: utf-8 -*-
"""최종 발표용 PPT 생성기 (RansomGuard EDR).
비전문가도 이해 가능한 10분 분량 슬라이드. 마지막은 시연영상 첨부 양식.
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ---- 색상 테마 ----
NAVY   = RGBColor(0x0F, 0x1B, 0x2D)   # 배경 진한 남색
NAVY2  = RGBColor(0x1B, 0x2C, 0x44)   # 카드 남색
WHITE  = RGBColor(0xF5, 0xF7, 0xFA)
GRAY   = RGBColor(0xB6, 0xC2, 0xD0)
RED    = RGBColor(0xE5, 0x3E, 0x3E)   # 위협/강조
TEAL   = RGBColor(0x2D, 0xD4, 0xBF)   # 방어/성공
AMBER  = RGBColor(0xF5, 0xB5, 0x42)   # 주의
BLUE   = RGBColor(0x4D, 0x8E, 0xF0)

FONT = "맑은 고딕"

prs = Presentation()
prs.slide_width  = Inches(13.333)
prs.slide_height = Inches(7.5)
SW, SH = prs.slide_width, prs.slide_height
BLANK = prs.slide_layouts[6]


def slide():
    s = prs.slides.add_slide(BLANK)
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SW, SH)
    bg.fill.solid(); bg.fill.fore_color.rgb = NAVY
    bg.line.fill.background()
    bg.shadow.inherit = False
    s.shapes._spTree.remove(bg._element)
    s.shapes._spTree.insert(2, bg._element)
    return s


def txt(s, x, y, w, h, text, size, color=WHITE, bold=False, align=PP_ALIGN.LEFT,
        anchor=MSO_ANCHOR.TOP, font=FONT, line_spacing=1.0, italic=False):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.line_spacing = line_spacing
        r = p.add_run(); r.text = ln
        f = r.font
        f.size = Pt(size); f.bold = bold; f.italic = italic
        f.color.rgb = color; f.name = font
    return tb


def card(s, x, y, w, h, fill=NAVY2, line=None):
    c = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    c.fill.solid(); c.fill.fore_color.rgb = fill
    if line:
        c.line.color.rgb = line; c.line.width = Pt(1.5)
    else:
        c.line.fill.background()
    c.shadow.inherit = False
    return c


def bar(s, x, y, w, h, color):
    b = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, x, y, w, h)
    b.fill.solid(); b.fill.fore_color.rgb = color
    b.line.fill.background(); b.shadow.inherit = False
    return b


def header(s, kicker, title, accent=TEAL):
    bar(s, Inches(0.6), Inches(0.55), Inches(0.16), Inches(0.95), accent)
    txt(s, Inches(0.95), Inches(0.5), Inches(11.5), Inches(0.4), kicker, 14, accent, bold=True)
    txt(s, Inches(0.95), Inches(0.85), Inches(11.8), Inches(0.8), title, 30, WHITE, bold=True)


# =====================================================================
# 1. 표지
# =====================================================================
s = slide()
bar(s, 0, Inches(3.05), SW, Inches(0.05), TEAL)
txt(s, Inches(1), Inches(1.7), Inches(11.3), Inches(0.5), "졸업 / 최종 프로젝트 발표", 18, TEAL, bold=True, align=PP_ALIGN.CENTER)
txt(s, Inches(1), Inches(2.2), Inches(11.3), Inches(1.0), "RansomGuard EDR", 54, WHITE, bold=True, align=PP_ALIGN.CENTER)
txt(s, Inches(1), Inches(3.25), Inches(11.3), Inches(0.7),
    "랜섬웨어를 스스로 탐지하고 즉시 차단하는 윈도우 보안 프로그램", 22, GRAY, align=PP_ALIGN.CENTER)
txt(s, Inches(1), Inches(4.5), Inches(11.3), Inches(0.5),
    "Windows 11 전용 · 실시간 행위 기반 탐지 + 자동 대응", 15, BLUE, align=PP_ALIGN.CENTER)
txt(s, Inches(1), Inches(6.4), Inches(11.3), Inches(0.5),
    "팀명 / 발표자 ·  2026", 14, GRAY, align=PP_ALIGN.CENTER)

# =====================================================================
# 2. 랜섬웨어란? (문제 제기)
# =====================================================================
s = slide()
header(s, "왜 이 프로젝트가 필요한가", "랜섬웨어 — 내 파일을 인질로 잡는 악성코드", RED)
txt(s, Inches(0.95), Inches(1.9), Inches(11.5), Inches(0.9),
    "어느 날 갑자기 내 사진·문서·업무 파일이 전부 암호화되어 열 수 없게 되고,\n"
    "\"돈을 보내면 풀어주겠다\"는 협박 메시지가 뜹니다. 이것이 랜섬웨어입니다.", 19, GRAY, line_spacing=1.2)

items = [
    ("📁", "한순간에 전부", "수천 개 파일이 몇 분 만에 암호화됩니다", RED),
    ("🔒", "복구 거의 불가", "백업·복원 지점까지 함께 지워버립니다", AMBER),
    ("💸", "막대한 피해", "기업·병원·개인 모두가 표적이 됩니다", BLUE),
]
cw = Inches(3.75); gap = Inches(0.3); x0 = Inches(0.95); y0 = Inches(3.3)
for i, (ic, t, d, col) in enumerate(items):
    x = x0 + i * (cw + gap)
    card(s, x, y0, cw, Inches(2.6))
    bar(s, x, y0, cw, Inches(0.12), col)
    txt(s, x, y0 + Inches(0.4), cw, Inches(0.8), ic, 40, align=PP_ALIGN.CENTER)
    txt(s, x + Inches(0.2), y0 + Inches(1.35), cw - Inches(0.4), Inches(0.5), t, 19, WHITE, bold=True, align=PP_ALIGN.CENTER)
    txt(s, x + Inches(0.25), y0 + Inches(1.85), cw - Inches(0.5), Inches(0.7), d, 14, GRAY, align=PP_ALIGN.CENTER)

# =====================================================================
# 3. 기존 백신의 한계 (AS-IS)
# =====================================================================
s = slide()
header(s, "현실의 문제점", "백신(Windows Defender)만으로는 부족합니다", AMBER)
txt(s, Inches(0.95), Inches(1.85), Inches(11.5), Inches(0.6),
    "기존 백신은 \"이미 알려진 악성코드\"를 이름표로 찾아냅니다. 그래서 —", 18, GRAY)

rows = [
    ("새로 나온 / 변형된 랜섬웨어", "이름표가 없어 그냥 통과됩니다"),
    ("백업·복원 지점 삭제 명령", "윈도우의 정상 명령으로 취급되어 안 막힙니다"),
    ("대량 파일 암호화 행동", "파일이 바뀌는 '행동' 자체는 감시하지 않습니다"),
    ("탐지 후 대응", "경고만 띄울 뿐, 스스로 멈추게 하지 못합니다"),
]
y = Inches(2.65)
for i, (a, b) in enumerate(rows):
    yy = y + i * Inches(0.95)
    card(s, Inches(0.95), yy, Inches(11.45), Inches(0.78), NAVY2)
    txt(s, Inches(1.2), yy, Inches(0.78), Inches(0.78), "✕", 24, RED, bold=True, anchor=MSO_ANCHOR.MIDDLE, align=PP_ALIGN.CENTER)
    txt(s, Inches(2.0), yy, Inches(4.3), Inches(0.78), a, 17, WHITE, bold=True, anchor=MSO_ANCHOR.MIDDLE)
    txt(s, Inches(6.4), yy, Inches(5.8), Inches(0.78), b, 15, GRAY, anchor=MSO_ANCHOR.MIDDLE)
txt(s, Inches(0.95), Inches(6.7), Inches(11.5), Inches(0.5),
    "→ \"알려진 것\"이 아니라 \"수상한 행동\"을 잡아야 한다는 것이 우리의 출발점입니다.", 16, TEAL, bold=True)

# =====================================================================
# 4. 우리가 만든 것 (비유)
# =====================================================================
s = slide()
header(s, "우리의 해결책", "RansomGuard — 컴퓨터를 위한 '무인 경비 시스템'", TEAL)
txt(s, Inches(0.95), Inches(1.85), Inches(11.5), Inches(0.9),
    "집에 CCTV·동작감지센서·경보기가 함께 작동하듯, RansomGuard는 컴퓨터 안에서\n"
    "파일을 노리는 수상한 움직임을 24시간 감시하고 스스로 대응합니다.", 19, GRAY, line_spacing=1.2)

cards = [
    ("👁", "감시한다", "파일에 무슨 일이 일어나는지\n실시간으로 지켜봅니다", BLUE),
    ("🧠", "판단한다", "여러 단서의 점수를 합산해\n위험도를 스스로 매깁니다", AMBER),
    ("🛡", "대응한다", "위험하면 그 프로그램을\n즉시 격리하고 종료합니다", TEAL),
]
cw = Inches(3.75); x0 = Inches(0.95); y0 = Inches(3.2)
for i, (ic, t, d, col) in enumerate(cards):
    x = x0 + i * (cw + Inches(0.3))
    card(s, x, y0, cw, Inches(2.9), NAVY2, line=col)
    txt(s, x, y0 + Inches(0.35), cw, Inches(0.9), ic, 44, align=PP_ALIGN.CENTER)
    txt(s, x, y0 + Inches(1.4), cw, Inches(0.5), t, 22, col, bold=True, align=PP_ALIGN.CENTER)
    txt(s, x + Inches(0.2), y0 + Inches(2.0), cw - Inches(0.4), Inches(0.8), d, 15, GRAY, align=PP_ALIGN.CENTER, line_spacing=1.15)
txt(s, Inches(0.95), Inches(6.45), Inches(11.5), Inches(0.5),
    "백신과 경쟁이 아니라, 백신이 놓치는 '행동'을 잡아 보완합니다.", 15, GRAY, italic=True, align=PP_ALIGN.CENTER)

# =====================================================================
# 5. 어떻게 동작하나 (흐름도)
# =====================================================================
s = slide()
header(s, "동작 원리 한눈에", "수상한 움직임 → 점수 합산 → 자동 차단", BLUE)

steps = [
    ("1", "감시", "커널(시스템 깊은 곳)에서\n모든 파일 변경을 포착", BLUE),
    ("2", "탐지", "암호화 흔적·미끼파일·\n위험 명령 등 단서 수집", AMBER),
    ("3", "채점", "2분 동안 단서 점수를 합산\n→ 위험 등급 판정", RED),
    ("4", "대응", "위험 프로그램을 격리 +\n즉시 종료, 보고서 작성", TEAL),
]
cw = Inches(2.75); gap = Inches(0.35); x0 = Inches(0.7); y0 = Inches(2.6)
for i, (n, t, d, col) in enumerate(steps):
    x = x0 + i * (cw + gap)
    card(s, x, y0, cw, Inches(2.5), NAVY2)
    bar(s, x, y0, cw, Inches(0.12), col)
    cnum = s.shapes.add_shape(MSO_SHAPE.OVAL, x + cw/2 - Inches(0.4), y0 + Inches(0.35), Inches(0.8), Inches(0.8))
    cnum.fill.solid(); cnum.fill.fore_color.rgb = col; cnum.line.fill.background(); cnum.shadow.inherit = False
    tf = cnum.text_frame; tf.word_wrap = True
    p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
    r = p.add_run(); r.text = n; r.font.size = Pt(28); r.font.bold = True; r.font.color.rgb = NAVY; r.font.name = FONT
    txt(s, x, y0 + Inches(1.35), cw, Inches(0.5), t, 21, WHITE, bold=True, align=PP_ALIGN.CENTER)
    txt(s, x + Inches(0.2), y0 + Inches(1.9), cw - Inches(0.4), Inches(0.55), d, 13, GRAY, align=PP_ALIGN.CENTER, line_spacing=1.1)
    if i < 3:
        txt(s, x + cw - Inches(0.05), y0 + Inches(0.9), Inches(0.5), Inches(0.6), "➜", 26, GRAY, align=PP_ALIGN.CENTER)

txt(s, Inches(0.7), Inches(5.5), Inches(11.9), Inches(0.45),
    "핵심: 단서 하나로 단정하지 않습니다. 점수를 합산해 오탐을 줄이고, 오래된 단서는 2분 뒤 자동 소멸합니다.",
    16, TEAL, bold=True, align=PP_ALIGN.CENTER)
txt(s, Inches(0.7), Inches(6.1), Inches(11.9), Inches(0.8),
    "INFO(정상) → LOW → MEDIUM → HIGH(위험) → CRITICAL(즉시 대응)  ·  5단계 위험 등급",
    15, GRAY, align=PP_ALIGN.CENTER)

# =====================================================================
# 6. 핵심 무기 4가지
# =====================================================================
s = slide()
header(s, "핵심 탐지 기능", "랜섬웨어를 잡는 4가지 '덫'", TEAL)
feats = [
    ("🪤", "미끼 파일 (Canary)", "사용자가 절대 안 건드리는 가짜 파일을 깔아둡니다. 여기에 손대는 순간 = 랜섬웨어 확정.", RED),
    ("📈", "대량 암호화 감지", "짧은 시간에 수많은 파일이 알아볼 수 없게 바뀌면(고엔트로피) 경보를 울립니다.", AMBER),
    ("⚙", "위험 명령 차단", "백업 삭제·백신 끄기·복구 무력화 같은 22종 위험 명령을 실시간 포착합니다.", BLUE),
    ("✂", "자동 종료 + 격리", "위험 프로그램을 커널 차원에서 차단하고 즉시 종료해 피해를 멈춥니다.", TEAL),
]
cw = Inches(5.6); ch = Inches(1.95); gx = Inches(0.95); gy = Inches(2.0)
for i, (ic, t, d, col) in enumerate(feats):
    x = gx + (i % 2) * (cw + Inches(0.25))
    y = gy + (i // 2) * (ch + Inches(0.3))
    card(s, x, y, cw, ch, NAVY2)
    bar(s, x, y, Inches(0.12), ch, col)
    txt(s, x + Inches(0.35), y + Inches(0.3), Inches(0.9), Inches(0.9), ic, 34)
    txt(s, x + Inches(1.35), y + Inches(0.28), cw - Inches(1.6), Inches(0.55), t, 19, col, bold=True)
    txt(s, x + Inches(1.35), y + Inches(0.85), cw - Inches(1.6), Inches(1.0), d, 14, GRAY, line_spacing=1.15)

# =====================================================================
# 7. 안전장치 (신뢰)
# =====================================================================
s = slide()
header(s, "함부로 끄거나 망가뜨릴 수 없게", "스스로를 지키는 안전장치", AMBER)
safe = [
    ("🚫", "절대 안 죽이는 목록", "lsass·csrss 등 시스템 핵심 프로그램은\n어떤 경우에도 종료하지 않아 컴퓨터를 보호합니다."),
    ("🔐", "변조 방지", "랜섬웨어가 RansomGuard 자체를 끄려 해도\n핸들 접근을 차단해 무력화를 막습니다."),
    ("❤", "워치독(감시견)", "5초마다 살아있는지 확인하고,\n꺼지거나 멈추면 자동으로 되살립니다."),
    ("📝", "사건 보고서", "대응할 때마다 무엇을·왜 했는지\n자동으로 기록을 남겨 사후 확인이 가능합니다."),
]
cw = Inches(5.6); ch = Inches(1.95); gx = Inches(0.95); gy = Inches(2.0)
for i, (ic, t, d) in enumerate(safe):
    x = gx + (i % 2) * (cw + Inches(0.25))
    y = gy + (i // 2) * (ch + Inches(0.3))
    card(s, x, y, cw, ch, NAVY2, line=TEAL)
    txt(s, x + Inches(0.35), y + Inches(0.35), Inches(0.9), Inches(0.9), ic, 32)
    txt(s, x + Inches(1.3), y + Inches(0.3), cw - Inches(1.6), Inches(0.55), t, 18, WHITE, bold=True)
    txt(s, x + Inches(1.3), y + Inches(0.85), cw - Inches(1.6), Inches(1.0), d, 14, GRAY, line_spacing=1.15)

# =====================================================================
# 8. 결과 / 성과
# =====================================================================
s = slide()
header(s, "검증 결과", "실제로 작동합니다", TEAL)
txt(s, Inches(0.95), Inches(1.8), Inches(11.5), Inches(0.5),
    "안전한 시뮬레이터부터 격리 VM의 실제 검체까지 단계적으로 검증했습니다.", 17, GRAY)

stats = [
    ("실검체", "격리 VM에서\n실제 랜섬웨어 탐지 성공", TEAL),
    ("2분 이내", "위험 등급 판정 →\n자동 대응까지", BLUE),
    ("0건", "보호 프로세스\n오종료 (안전장치 작동)", AMBER),
]
cw = Inches(3.75); x0 = Inches(0.95); y0 = Inches(2.55)
for i, (big, d, col) in enumerate(stats):
    x = x0 + i * (cw + Inches(0.3))
    card(s, x, y0, cw, Inches(2.0), NAVY2)
    bar(s, x, y0, cw, Inches(0.12), col)
    txt(s, x, y0 + Inches(0.4), cw, Inches(0.8), big, 32, col, bold=True, align=PP_ALIGN.CENTER)
    txt(s, x + Inches(0.2), y0 + Inches(1.3), cw - Inches(0.4), Inches(0.6), d, 14, GRAY, align=PP_ALIGN.CENTER, line_spacing=1.1)

card(s, Inches(0.95), Inches(4.85), Inches(11.45), Inches(1.85), NAVY2, line=TEAL)
txt(s, Inches(1.25), Inches(5.05), Inches(11.0), Inches(0.4), "✓ 무엇을 확인했나", 16, TEAL, bold=True)
txt(s, Inches(1.25), Inches(5.5), Inches(11.0), Inches(1.1),
    "•  안전 시뮬레이터로 암호화·미끼·백업삭제·부팅조작 등 전 시나리오 탐지 검증 (실제 피해 없이)\n"
    "•  네트워크 격리 VM에서 실제 검체를 터뜨려 탐지·대응 동작 확인\n"
    "•  BSOD가 나도 디스크 기록만으로 성적을 집계하는 사후분석(postmortem) 체계 구축",
    15, GRAY, line_spacing=1.25)

# =====================================================================
# 9. 만든 것의 규모 (산출물)
# =====================================================================
s = slide()
header(s, "프로젝트 규모", "우리가 6주간 만든 것", BLUE)
left = [
    ("커널 드라이버", "C로 작성한 파일시스템 미니필터 (RansomGuard.sys)"),
    ("탐지 엔진", "7종 행위 탐지기 + 점수 채점 엔진 (Python)"),
    ("자동 대응", "격리·종료 + 변조방지 + 워치독 서비스"),
    ("대시보드", "실시간 모니터링 웹 화면 + 사건 보고서 자동 생성"),
]
right = [
    ("6 / 20 / 62", "대분류 / 중분류 / 소분류 기능"),
    ("22종", "위험 명령 탐지 룰"),
    ("4종 문서", "기능명세서·AS-IS·WBS·프로세스도 + 한·영 위키"),
    ("원클릭 설치", "PowerShell 스크립트로 빌드·설치·운영 자동화"),
]
txt(s, Inches(0.95), Inches(1.85), Inches(5.6), Inches(0.4), "■ 만든 구성요소", 17, TEAL, bold=True)
for i, (t, d) in enumerate(left):
    y = Inches(2.4) + i * Inches(1.05)
    card(s, Inches(0.95), y, Inches(5.6), Inches(0.9), NAVY2)
    txt(s, Inches(1.2), y + Inches(0.12), Inches(5.2), Inches(0.4), t, 16, WHITE, bold=True)
    txt(s, Inches(1.2), y + Inches(0.5), Inches(5.2), Inches(0.35), d, 12.5, GRAY)

txt(s, Inches(6.75), Inches(1.85), Inches(5.6), Inches(0.4), "■ 숫자로 보는 산출물", 17, AMBER, bold=True)
for i, (t, d) in enumerate(right):
    y = Inches(2.4) + i * Inches(1.05)
    card(s, Inches(6.75), y, Inches(5.6), Inches(0.9), NAVY2)
    txt(s, Inches(7.0), y + Inches(0.1), Inches(2.5), Inches(0.6), t, 19, AMBER, bold=True, anchor=MSO_ANCHOR.MIDDLE)
    txt(s, Inches(9.4), y + Inches(0.1), Inches(2.85), Inches(0.6), d, 12.5, GRAY, anchor=MSO_ANCHOR.MIDDLE)

# =====================================================================
# 10. 한계와 향후 과제
# =====================================================================
s = slide()
header(s, "솔직한 한계와 다음 단계", "아직 남은 과제", AMBER)
txt(s, Inches(0.95), Inches(1.85), Inches(11.5), Inches(0.5),
    "연구·학습용 프로토타입입니다. 다음을 보완하면 실사용에 더 가까워집니다.", 17, GRAY)
gaps = [
    ("정상 프로그램 화이트리스트", "서명된 정상 프로그램을 더 확실히 구분해 오탐을 줄이기"),
    ("느린 암호화(수 시간) 대응", "2분 채점 창을 넘기는 '천천히' 공격까지 포착하기"),
    ("포렌식 기록 강화", "사후 분석을 위한 커널 단계 컨텍스트 저장 확대"),
]
for i, (t, d) in enumerate(gaps):
    y = Inches(2.55) + i * Inches(1.15)
    card(s, Inches(0.95), y, Inches(11.45), Inches(0.95), NAVY2)
    bar(s, Inches(0.95), y, Inches(0.12), Inches(0.95), AMBER)
    txt(s, Inches(1.35), y + Inches(0.14), Inches(11.0), Inches(0.45), t, 17, WHITE, bold=True)
    txt(s, Inches(1.35), y + Inches(0.55), Inches(11.0), Inches(0.35), d, 14, GRAY)

# =====================================================================
# 11. 시연 영상 (placeholder 양식)
# =====================================================================
s = slide()
bar(s, 0, Inches(0.55), SW, Inches(0.05), TEAL)
txt(s, Inches(0.6), Inches(0.7), Inches(12), Inches(0.5), "DEMO", 16, TEAL, bold=True, align=PP_ALIGN.CENTER)
txt(s, Inches(0.6), Inches(1.05), Inches(12), Inches(0.7), "시연 영상", 34, WHITE, bold=True, align=PP_ALIGN.CENTER)

# 영상 자리 (검정 박스 + 재생버튼)
vx, vy, vw, vh = Inches(2.4), Inches(2.1), Inches(8.5), Inches(4.0)
box = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, vx, vy, vw, vh)
box.fill.solid(); box.fill.fore_color.rgb = RGBColor(0x00, 0x00, 0x00)
box.line.color.rgb = TEAL; box.line.width = Pt(2); box.shadow.inherit = False
play = s.shapes.add_shape(MSO_SHAPE.OVAL, vx + vw/2 - Inches(0.7), vy + vh/2 - Inches(0.7), Inches(1.4), Inches(1.4))
play.fill.solid(); play.fill.fore_color.rgb = TEAL; play.line.fill.background(); play.shadow.inherit = False
tri = s.shapes.add_shape(MSO_SHAPE.ISOSCELES_TRIANGLE, vx + vw/2 - Inches(0.25), vy + vh/2 - Inches(0.35), Inches(0.6), Inches(0.7))
tri.rotation = 90
tri.fill.solid(); tri.fill.fore_color.rgb = NAVY; tri.line.fill.background(); tri.shadow.inherit = False
txt(s, vx, vy + vh - Inches(0.85), vw, Inches(0.6),
    "▶ 여기에 시연 영상을 삽입하세요  (삽입 ▸ 비디오 ▸ 이 디바이스의 비디오)",
    14, GRAY, align=PP_ALIGN.CENTER)

txt(s, Inches(0.6), Inches(6.4), Inches(12.1), Inches(0.9),
    "추천 시연 흐름:  ① 에이전트 실행 → ② 시뮬레이터로 대량 암호화 발생 → "
    "③ 대시보드 점수 급상승(CRITICAL) → ④ 자동 종료 + 사건 보고서 생성",
    14, GRAY, align=PP_ALIGN.CENTER, line_spacing=1.2)

out = "docs/RansomGuard_최종발표.pptx"
prs.save(out)
print("saved:", out, "| slides:", len(prs.slides._sldIdLst))
