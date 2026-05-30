"""
Console encoding helper
-----------------------
Windows 콘솔이 cp949 같은 비 UTF-8 코드페이지일 때, em-dash(—)나 박스/바
문자(░▓─)를 ``print`` 하면 ``UnicodeEncodeError`` 로 프로세스가 죽는다.
특히 stdout 이 리다이렉트(서비스 Session 0 / 파이프 / 파일)되면 Python 이
대화형 ``WriteConsoleW`` 대신 로캘 인코딩으로 떨어지면서 재현된다.

엔트리포인트 시작 시 한 번 ``force_utf8()`` 을 호출해 stdout/stderr 를
UTF-8(대체 문자 허용)로 맞춰 두면, 어떤 콘솔/서비스에서도 안전하다.
"""

from __future__ import annotations

import sys


def force_utf8() -> None:
    """stdout/stderr 를 UTF-8(errors='replace')로 재설정. 실패해도 무해."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue  # None(서비스) 또는 reconfigure 미지원 스트림
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
