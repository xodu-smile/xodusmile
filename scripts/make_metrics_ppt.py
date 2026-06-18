# -*- coding: utf-8 -*-
"""오탐·미탐 측정 결과 발표 슬라이드 생성기 (RansomGuard EDR).

reports/fp_fn_metrics.json (tests/fp_fn_benchmark.py 산출물)을 읽어
발표용 PPTX 를 만든다.  matplotlib 없이 python-pptx 네이티브 표/도형으로
그리므로 슬라이드 위에서 그대로 편집 가능하다.

구성:
  1) 표지 — 측정 개요 / 방법론
  2) 혼동행렬 + 핵심 지표(오탐률·미탐률 강조)
  3) 지표 KPI 카드 (정확도/정밀도/재현율/특이도/F1)
  4) 시나리오별 상세 표
  5) 미탐 분석 & 오탐 억제 설계 포인트

실행:  python scripts/make_metrics_ppt.py
출력:  docs/RansomGuard_오탐미탐_측정결과.pptx
"""
from __future__ import annotations

import json
from pathlib import Path

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# ---- 색상 테마 (make_report_ppt.py 와 통일된 라이트 테마) ----
BG    = RGBColor(0xF4, 0xF7, 0xFB)
CARD  = RGBColor(0xFF, 0xFF, 0xFF)
LINE  = RGBColor(0xD8, 0xDF, 0xEA)
INK   = RGBColor(0x16, 0x26, 0x3B)
MUTED = RGBColor(0x52, 0x62, 0x78)
RED   = RGBColor(0xD3, 0x2F, 0x2F)
GREEN = RGBColor(0x1B, 0x8A, 0x4E)
TEAL  = RGBColor(0x0E, 0x93, 0x86)
AMBER = RGBColor(0xB9, 0x73, 0x00)
BLUE  = RGBColor(0x25, 0x63, 0xC9)
GREENBG = RGBColor(0xE6, 0xF4, 0xEA)
REDBG   = RGBColor(0xFD, 0xEC, 0xEA)
BLUEBG  = RGBColor(0xE8, 0xF0, 0xFC)
AMBERBG = RGBColor(0xFB, 0xF1, 0xDE)

FONT = "맑은 고딕"

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "reports" / "fp_fn_metrics.json"
OUT = ROOT / "docs" / "RansomGuard_오탐미탐_측정결과.pptx"

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
SW, SH = prs.slide_width, prs.slide_height
BLANK = prs.slide_layouts[6]


# --------------------------------------------------------------------------
# 도형/텍스트 헬퍼
# --------------------------------------------------------------------------
def slide():
    s = prs.slides.add_slide(BLANK)
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SW, SH)
    bg.fill.solid(); bg.fill.fore_color.rgb = BG
    bg.line.fill.background(); bg.shadow.inherit = False
    s.shapes._spTree.remove(bg._element)
    s.shapes._spTree.insert(2, bg._element)
    return s


def txt(s, x, y, w, h, text, size, color=INK, bold=False, align=PP_ALIGN.LEFT,
        anchor=MSO_ANCHOR.TOP, font=FONT, line_spacing=1.05, italic=False):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    for i, ln in enumerate(text.split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.line_spacing = line_spacing
        r = p.add_run(); r.text = ln
        r.font.size = Pt(size); r.font.bold = bold; r.font.italic = italic
        r.font.name = font; r.font.color.rgb = color
    return tb


def card(s, x, y, w, h, fill=CARD, line=LINE, radius=True):
    shp = s.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE, x, y, w, h)
    shp.fill.solid(); shp.fill.fore_color.rgb = fill
    shp.line.color.rgb = line; shp.line.width = Pt(1)
    shp.shadow.inherit = False
    return shp


def header(s, title, subtitle=""):
    bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SW, Inches(1.0))
    bar.fill.solid(); bar.fill.fore_color.rgb = INK
    bar.line.fill.background(); bar.shadow.inherit = False
    txt(s, Inches(0.5), Inches(0.12), Inches(11), Inches(0.55), title, 26,
        color=CARD, bold=True)
    if subtitle:
        txt(s, Inches(0.52), Inches(0.66), Inches(12), Inches(0.3), subtitle, 12,
            color=RGBColor(0xC6, 0xD2, 0xE2))


def pct(x):
    return f"{x * 100:.1f}%"


# --------------------------------------------------------------------------
def main():
    data = json.loads(DATA.read_text(encoding="utf-8"))
    m = data["summary"]
    c = m["counts"]
    mt = m["metrics"]
    results = data["results"]

    # ===== 슬라이드 1 — 표지 / 개요 =====
    s = slide()
    accent = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.28), SH)
    accent.fill.solid(); accent.fill.fore_color.rgb = TEAL
    accent.line.fill.background(); accent.shadow.inherit = False

    txt(s, Inches(0.9), Inches(1.4), Inches(11.5), Inches(0.5),
        "RansomGuard EDR", 22, color=TEAL, bold=True)
    txt(s, Inches(0.9), Inches(1.95), Inches(11.5), Inches(1.0),
        "오탐·미탐 정량 측정 결과", 44, color=INK, bold=True)
    txt(s, Inches(0.9), Inches(3.05), Inches(11.5), Inches(0.5),
        "False Positive / False Negative Benchmark", 18, color=MUTED)

    # 개요 카드 3개
    cards = [
        (f"{c['total']}", "측정 시나리오", f"악성 {c['positives']} · 정상 {c['negatives']}", BLUE, BLUEBG),
        (pct(mt["accuracy"]), "정확도 Accuracy", "전체 판정 정확도", GREEN, GREENBG),
        (pct(mt["fpr"]) + " / " + pct(mt["fnr"]), "오탐률 / 미탐률", "FPR / FNR", RED, REDBG),
    ]
    cw, gap = Inches(3.7), Inches(0.35)
    x0 = Inches(0.9)
    for i, (big, lab, sub, fg, bgc) in enumerate(cards):
        x = x0 + i * (cw + gap)
        card(s, x, Inches(3.9), cw, Inches(1.9), fill=bgc, line=bgc)
        txt(s, x, Inches(4.1), cw, Inches(0.8), big, 34, color=fg, bold=True,
            align=PP_ALIGN.CENTER)
        txt(s, x, Inches(4.95), cw, Inches(0.4), lab, 15, color=INK, bold=True,
            align=PP_ALIGN.CENTER)
        txt(s, x, Inches(5.35), cw, Inches(0.4), sub, 11, color=MUTED,
            align=PP_ALIGN.CENTER)

    txt(s, Inches(0.9), Inches(6.2), Inches(11.6), Inches(1.0),
        "방법론: 실제 탐지기(mass_io·canary·ransom_note·process_cmdline)와 ScoringEngine을 그대로 구동해\n"
        "라벨이 붙은 행위 시나리오를 통과시켜 측정.  탐지 기준 = 위협레벨≥HIGH 또는 CRITICAL신호 또는 (HIGH신호+암호화 보강).",
        12, color=MUTED, line_spacing=1.2)
    txt(s, Inches(0.9), Inches(7.05), Inches(11.6), Inches(0.3),
        f"생성 일시: {m['generated_at']}", 10, color=MUTED)

    # ===== 슬라이드 2 — 혼동행렬 + 핵심 지표 =====
    s = slide()
    header(s, "혼동행렬 & 핵심 지표", "Confusion Matrix · 오탐률(FPR)·미탐률(FNR) 중심")

    # 혼동행렬 2x2
    gx, gy = Inches(0.7), Inches(1.65)
    cellw, cellh = Inches(2.6), Inches(1.55)
    lblw = Inches(1.4)
    # 컬럼 헤더
    txt(s, gx + lblw, gy - Inches(0.5), cellw, Inches(0.4), "예측: 악성(탐지)", 13,
        bold=True, align=PP_ALIGN.CENTER, color=INK)
    txt(s, gx + lblw + cellw, gy - Inches(0.5), cellw, Inches(0.4), "예측: 정상(미탐지)",
        13, bold=True, align=PP_ALIGN.CENTER, color=INK)
    # 행 헤더
    txt(s, gx - Inches(0.05), gy + Inches(0.5), lblw, Inches(0.5), "실제\n악성", 13,
        bold=True, align=PP_ALIGN.CENTER, color=INK, anchor=MSO_ANCHOR.MIDDLE)
    txt(s, gx - Inches(0.05), gy + cellh + Inches(0.5), lblw, Inches(0.5), "실제\n정상",
        13, bold=True, align=PP_ALIGN.CENTER, color=INK, anchor=MSO_ANCHOR.MIDDLE)

    matrix = [
        (0, 0, "TP", c["TP"], "정탐", GREEN, GREENBG),
        (0, 1, "FN", c["FN"], "미탐 (놓침)", RED, REDBG),
        (1, 0, "FP", c["FP"], "오탐 (정상을 차단)", RED, REDBG),
        (1, 1, "TN", c["TN"], "정상 통과", GREEN, GREENBG),
    ]
    for row, col, key, val, lab, fg, bgc in matrix:
        x = gx + lblw + col * cellw
        y = gy + row * cellh
        card(s, x, y, cellw - Inches(0.1), cellh - Inches(0.1), fill=bgc, line=LINE)
        txt(s, x, y + Inches(0.12), cellw - Inches(0.1), Inches(0.4), key, 14,
            color=fg, bold=True, align=PP_ALIGN.CENTER)
        txt(s, x, y + Inches(0.45), cellw - Inches(0.1), Inches(0.6), str(val), 40,
            color=fg, bold=True, align=PP_ALIGN.CENTER)
        txt(s, x, y + Inches(1.08), cellw - Inches(0.1), Inches(0.35), lab, 11,
            color=MUTED, align=PP_ALIGN.CENTER)

    # 우측 핵심 지표 강조 (오탐률/미탐률)
    rx = gx + lblw + 2 * cellw + Inches(0.5)
    rw = SW - rx - Inches(0.5)
    big_metrics = [
        ("오탐률 (FPR)", pct(mt["fpr"]), "정상을 랜섬웨어로 오인한 비율", RED, REDBG),
        ("미탐률 (FNR)", pct(mt["fnr"]), "랜섬웨어를 놓친 비율", AMBER, AMBERBG),
    ]
    for i, (lab, val, sub, fg, bgc) in enumerate(big_metrics):
        y = gy + i * Inches(1.6)
        card(s, rx, y, rw, Inches(1.4), fill=bgc, line=bgc)
        txt(s, rx + Inches(0.3), y + Inches(0.15), rw, Inches(0.4), lab, 15,
            color=INK, bold=True)
        txt(s, rx + Inches(0.3), y + Inches(0.5), rw, Inches(0.7), val, 40,
            color=fg, bold=True)
        txt(s, rx + Inches(0.3), y + Inches(1.02), rw, Inches(0.3), sub, 11,
            color=MUTED)

    # 하단 요약 지표 띠
    by = Inches(5.55)
    strip = [
        ("정밀도 Precision", pct(mt["precision"]), GREEN),
        ("재현율 Recall(탐지율)", pct(mt["recall"]), BLUE),
        ("특이도 Specificity", pct(mt["specificity"]), TEAL),
        ("F1 Score", pct(mt["f1"]), INK),
    ]
    sw_ = (SW - Inches(1.0)) / 4
    for i, (lab, val, fg) in enumerate(strip):
        x = Inches(0.5) + i * sw_
        card(s, x + Inches(0.05), by, sw_ - Inches(0.1), Inches(1.2))
        txt(s, x, by + Inches(0.15), sw_, Inches(0.55), val, 28, color=fg,
            bold=True, align=PP_ALIGN.CENTER)
        txt(s, x, by + Inches(0.78), sw_, Inches(0.35), lab, 12, color=MUTED,
            align=PP_ALIGN.CENTER)

    txt(s, Inches(0.5), Inches(6.95), Inches(12.3), Inches(0.4),
        f"※ 탐지 기준: {m['detection_rule']}", 10, color=MUTED)

    # ===== 슬라이드 3 — 시나리오별 상세 표 =====
    s = slide()
    header(s, "시나리오별 측정 상세",
           f"총 {c['total']}개 — 악성 {c['positives']} · 정상 {c['negatives']}  (✔ 정답 / ✗ 오류)")
    _scenario_table(s, results)

    # ===== 슬라이드 4 — 미탐 분석 & 오탐 억제 설계 =====
    s = slide()
    header(s, "결과 해석 — 오탐 억제와 미탐 한계",
           "왜 오탐 0%인가 · 유일한 미탐의 원인과 완화")

    half = (SW - Inches(1.5)) / 2
    # 좌: 오탐 억제 설계
    lx = Inches(0.5)
    card(s, lx, Inches(1.3), half, Inches(5.5), fill=GREENBG, line=GREENBG)
    txt(s, lx + Inches(0.35), Inches(1.5), half - Inches(0.6), Inches(0.5),
        f"오탐(FP) {c['FP']}건 — 오탐률 {pct(mt['fpr'])}", 18, color=GREEN, bold=True)
    fp_points = [
        "native 고엔트로피 형식 제외 — 사진(JPEG)·동영상(MP4)·압축(ZIP)\n  재저장을 암호화로 오인하지 않음",
        "노이즈 경로/확장자 필터 — 브라우저 캐시·빌드 임시파일(.tmp/.log)\n  대량 변경을 무시",
        "상관(correlation) 게이트 — 단일 파일 삭제는 암호화 활동이\n  동반될 때만 채점",
        "신뢰 actor 게이트 — Windows 서비싱(TiWorker) 정상 버스트 제외",
        "보강(corroboration) 요구 — 단독 HIGH(예: BitLocker 활성화)는\n  암호화 활동/2차 탐지 없으면 차단 안 함",
        "협박문 내용 확인 — '강 지표(지갑주소/onion)' 없으면 보안문서를\n  협박문으로 오인하지 않음",
    ]
    txt(s, lx + Inches(0.35), Inches(2.1), half - Inches(0.6), Inches(4.6),
        "\n".join("• " + p for p in fp_points), 12.5, color=INK, line_spacing=1.25)

    # 우: 미탐 분석
    rx = Inches(0.5) + half + Inches(0.5)
    card(s, rx, Inches(1.3), half, Inches(5.5), fill=AMBERBG, line=AMBERBG)
    txt(s, rx + Inches(0.35), Inches(1.5), half - Inches(0.6), Inches(0.5),
        f"미탐(FN) {c['FN']}건 — 미탐률 {pct(mt['fnr'])}", 18, color=AMBER, bold=True)
    fns = [r for r in results if r["outcome"] == "FN"]
    fn_txt = []
    for r in fns:
        fn_txt.append(f"▸ {r['title_ko']}\n   {r['desc_ko']}")
    if not fn_txt:
        fn_txt = ["(미탐 사례 없음)"]
    txt(s, rx + Inches(0.35), Inches(2.1), half - Inches(0.6), Inches(1.7),
        "\n".join(fn_txt), 12.5, color=INK, line_spacing=1.2)
    txt(s, rx + Inches(0.35), Inches(3.9), half - Inches(0.6), Inches(0.45),
        "완화 방안 (다층 방어)", 14, color=INK, bold=True)
    mitig = [
        "Canary 디코이 — 공격자가 파일 열거 중 미끼를 건드리면\n  확장자와 무관하게 즉시 CRITICAL 탐지",
        "커널 미니필터 — PID 단위 쓰기/이름변경 버스트를 확장자\n  의존 없이 관측 (사용자모드 휴리스틱 사각지대 보완)",
        "실검체 검증 — 격리 VM 실랜섬웨어 시험에서 탐지·능동대응\n  동작 확인 완료",
    ]
    txt(s, rx + Inches(0.35), Inches(4.4), half - Inches(0.6), Inches(2.3),
        "\n".join("• " + p for p in mitig), 12.5, color=INK, line_spacing=1.25)

    prs.save(str(OUT))
    print(f"[ok] 발표 슬라이드 생성: {OUT}")
    print(f"     슬라이드 {len(prs.slides._sldIdLst)}장")


def _scenario_table(s, results):
    """시나리오 상세 표 — 좌(악성) / 우(정상) 2단으로 나눠 한 슬라이드에."""
    mal = [r for r in results if r["label"] == "malicious"]
    ben = [r for r in results if r["label"] == "benign"]

    def draw(items, x, w, title, title_color):
        txt(s, x, Inches(1.25), w, Inches(0.4), title, 15, color=title_color,
            bold=True)
        from pptx.util import Emu as _E
        rows = len(items) + 1
        tbl_shape = s.shapes.add_table(rows, 4, x, Inches(1.7), w, Inches(0.4) * rows)
        table = tbl_shape.table
        # 컬럼 폭
        table.columns[0].width = int(w * 0.50)
        table.columns[1].width = int(w * 0.16)
        table.columns[2].width = int(w * 0.18)
        table.columns[3].width = int(w * 0.16)
        heads = ["시나리오", "점수", "레벨", "결과"]
        for j, htext in enumerate(heads):
            cell = table.cell(0, j)
            cell.text = htext
            _style_cell(cell, INK, CARD, bold=True, size=11,
                        align=PP_ALIGN.CENTER)
        for i, r in enumerate(items, start=1):
            ok = r["outcome"] in ("TP", "TN")
            res_txt = {"TP": "정탐 ✔", "TN": "정상 ✔",
                       "FP": "오탐 ✗", "FN": "미탐 ✗"}[r["outcome"]]
            res_color = GREEN if ok else RED
            rowbg = CARD if ok else REDBG
            vals = [r["title_ko"], str(r["score"]), r["level"], res_txt]
            for j, v in enumerate(vals):
                cell = table.cell(i, j)
                cell.text = v
                col = res_color if j == 3 else INK
                _style_cell(cell, col, rowbg, bold=(j == 3), size=10,
                            align=PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER)

    gap = Inches(0.4)
    w = (SW - Inches(1.0) - gap) / 2
    draw(mal, Inches(0.5), w, f"■ 악성 시나리오 ({len(mal)}) — 탐지 기대", RED)
    draw(ben, Inches(0.5) + w + gap, w, f"■ 정상 시나리오 ({len(ben)}) — 미탐지 기대", BLUE)


def _style_cell(cell, fg, bg, bold=False, size=10, align=PP_ALIGN.LEFT):
    cell.fill.solid(); cell.fill.fore_color.rgb = bg
    cell.vertical_anchor = MSO_ANCHOR.MIDDLE
    cell.margin_left = Inches(0.06); cell.margin_right = Inches(0.04)
    cell.margin_top = Inches(0.01); cell.margin_bottom = Inches(0.01)
    tf = cell.text_frame
    tf.word_wrap = True
    for p in tf.paragraphs:
        p.alignment = align
        for r in p.runs:
            r.font.size = Pt(size); r.font.bold = bold
            r.font.name = FONT; r.font.color.rgb = fg


if __name__ == "__main__":
    main()
