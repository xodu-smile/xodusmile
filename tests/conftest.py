"""
conftest.py — pytest configuration for RansomGuard EDR tests.

Adds repo root to sys.path so all project modules are importable
without installation (mirrors tests/simulator.py lines 22-23).
Registers the `windows` marker so collection never hard-fails on Linux.
"""

import sys
from pathlib import Path

import pytest

# Make repo root importable (scoring, attack_map, allowlist, detectors, …)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "windows: mark test as Windows-only (psutil/wmi/win32 required)",
    )
