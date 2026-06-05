"""
Registry Kernel Detector
------------------------
Subscribes to the kernel minifilter bridge's Registry events (sourced
from ``CmRegisterCallbackEx``) and scores writes/deletes against a
small set of high-value keys: Microsoft Defender configuration, common
persistence locations (Run / RunOnce / scheduled-task surrogates), and
the RansomGuard service registry entry (so we can detect attempts to
disable or unload our own driver).

The driver itself already pre-filters to a watch list, so every event
reaching this detector is interesting; the detector's job is to map
the key path → a labelled signal with an appropriate weight.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Detector
from scoring import Signal, Severity

if TYPE_CHECKING:
    from .minifilter_bridge import MinifilterBridge, RG_EVENT


REG_SET_VALUE     = 1
REG_DELETE_VALUE  = 2
REG_CREATE_KEY    = 3
REG_DELETE_KEY    = 4
REG_RENAME_KEY    = 5


# Lower-case substring → (signal name, weight, severity, message).
# Order matters: the first match wins.  Anything not matched falls
# through to a low-severity generic signal so we don't lose telemetry.
_PATTERNS = [
    (
        "\\system\\currentcontrolset\\services\\ransomguard",
        ("ransomguard_service_tamper", 80, Severity.CRITICAL,
         "Attempt to modify RansomGuard service registry entry"),
    ),
    (
        "\\windefend",
        ("defender_service_tamper", 70, Severity.CRITICAL,
         "Attempt to modify Windows Defender service registry"),
    ),
    (
        "\\wdfilter",
        ("defender_filter_tamper", 70, Severity.CRITICAL,
         "Attempt to modify Defender minifilter (WdFilter) service registry"),
    ),
    (
        "\\sense",
        ("mdatp_sense_tamper", 60, Severity.HIGH,
         "Attempt to modify Defender for Endpoint Sense service registry"),
    ),
    (
        "\\software\\microsoft\\windows defender",
        ("defender_settings_tamper", 55, Severity.HIGH,
         "Write to Windows Defender configuration key"),
    ),
    (
        "\\software\\policies\\microsoft\\windows defender",
        ("defender_policy_tamper", 60, Severity.HIGH,
         "Write to Windows Defender policy key (tamper)"),
    ),
    (
        "\\control\\safeboot",
        ("safeboot_tamper", 55, Severity.HIGH,
         "Write to SafeBoot control key (boot-into-safe-mode persistence)"),
    ),
    (
        "\\currentversion\\runonce",
        ("runonce_persistence", 35, Severity.MEDIUM,
         "Write to RunOnce persistence key"),
    ),
    (
        "\\currentversion\\run",
        ("run_key_persistence", 35, Severity.MEDIUM,
         "Write to Run persistence key"),
    ),
    (
        "\\currentversion\\policies\\system",
        ("system_policy_tamper", 40, Severity.MEDIUM,
         "Write to System policy key (UAC / SmartScreen / etc.)"),
    ),
]


def _classify(key_path_lc: str):
    for needle, sig in _PATTERNS:
        if needle in key_path_lc:
            return sig
    return ("registry_watched", 5, Severity.LOW, "Watched-key write")


# Benign value-name writes that fire the rules above as pure false
# positives.  Keyed by signal name → set of lower-cased value names to
# ignore.  Observed in live runs:
#   - ctfmon rewrites "internat.exe" under HKCU\...\Run constantly (legacy
#     input-locale switcher) → run_key_persistence spam.
#   - Defender (MsMpEng) writes its own telemetry timestamps to its config
#     key → defender_settings_tamper spam.
# These are narrow value-name allowlists; malware persistence under other
# value names (e.g. "UpdateTask") still scores normally.
_BENIGN_VALUES = {
    "run_key_persistence":    {"internat.exe"},
    "runonce_persistence":    {"internat.exe"},
    "defender_settings_tamper": {
        "sigupdatetimestampssincelasthb",
        "lastmapssuccesstime",
        "lastmapsfailuretime",
    },
}


class RegistryKernelDetector(Detector):
    """Callback-driven; no thread loop of its own."""

    name = "registry_kernel"

    def __init__(self, engine, bridge: "MinifilterBridge"):
        super().__init__(engine)
        self._bridge = bridge
        bridge.subscribe_registry(self._on_event)

    def run(self) -> None:
        self._stop_event.wait()

    # -------------------------------------------------------------- handlers

    def _on_event(self, evt: "RG_EVENT") -> None:
        sub = int(evt.SubKind)
        # Reads are filtered out at the driver, but be defensive.
        if sub not in (REG_SET_VALUE, REG_DELETE_VALUE, REG_CREATE_KEY,
                       REG_DELETE_KEY, REG_RENAME_KEY):
            return

        key = evt.Path[:max(0, int(evt.PathLength) - 1)] if evt.PathLength else ""
        value = evt.Extra[:max(0, int(evt.ExtraLength) - 1)] if evt.ExtraLength else ""
        pid = int(evt.ProcessId)
        if not key:
            return

        sig_name, weight, severity, base_msg = _classify(key.lower())

        # Drop known-benign value writes (legacy input switcher, Defender's
        # own telemetry) so they don't pin the score with false positives.
        benign = _BENIGN_VALUES.get(sig_name)
        if benign and value and value.lower() in benign:
            return

        op = {
            REG_SET_VALUE: "set",
            REG_DELETE_VALUE: "delete-value",
            REG_CREATE_KEY: "create-key",
            REG_DELETE_KEY: "delete-key",
            REG_RENAME_KEY: "rename-key",
        }[sub]

        msg = f"{base_msg} ({op}) pid={pid} key={key}"
        if value:
            msg += f" value={value}"

        self.emit(Signal(
            detector=self.name,
            name=sig_name,
            weight=weight,
            severity=severity,
            message=msg,
            metadata={
                "pid": pid,
                "key": key,
                "value": value,
                "op": op,
            },
        ))
