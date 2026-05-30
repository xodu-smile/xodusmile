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
from actor_trust import is_trusted_defender_actor

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
    (
        "\\image file execution options",
        ("ifeo_hijack", 60, Severity.HIGH,
         "Write to Image File Execution Options (debugger hijack / persistence)"),
    ),
    (
        "\\schedule\\taskcache",
        ("schtasks_persistence", 35, Severity.MEDIUM,
         "Write to scheduled-task cache (schtasks persistence)"),
    ),
]


# Value names under the Defender settings/policy keys that actually *weaken*
# protection.  Writing one of these is the tamper we care about.  Defender's
# own housekeeping (signature-update bookkeeping, telemetry, last-scan stamps,
# e.g. ``SignatureUpdatePending``) touches the same key constantly and is
# benign — so a write to this key is only HIGH when it names a disabling value.
#
# Split by what the *name alone* tells us, because the kernel event carries the
# value NAME but not the DWORD data (see _on_event):
#
#  - ALWAYS_ANOMALOUS: protection-*disabling* names the Defender engine does not
#    write as part of normal operation (DisableRealtimeMonitoring, …).  The name
#    alone implies weakening, so even the verified engine touching one is
#    suspicious (injection/impersonation) and must leave a signal.
#  - DIRECTION_DEPENDENT: protection names Defender writes in the *enabling*
#    direction all the time (TamperProtection=1, SpyNet consent…).  Without the
#    DWORD we can't tell enable from disable, so from the real engine we treat
#    these as self-config; from anyone else they're tamper.
DEFENDER_ALWAYS_ANOMALOUS_VALUES = frozenset({
    "disableantispyware",
    "disableantivirus",
    "disablerealtimemonitoring",
    "disablebehaviormonitoring",
    "disableonaccessprotection",
    "disableioavprotection",
    "disablescriptscanning",
    "disablescanonrealtimeenable",
    "disableblockatfirstseen",
    "disablearchivescanning",
    "disableenhancednotifications",
})

DEFENDER_DIRECTION_DEPENDENT_VALUES = frozenset({
    "tamperprotection",
    "spynetreporting",
    "submitsamplesconsent",
    "puaprotection",
})

# Union: any of these names written by a *non-Defender* actor is tamper.
DEFENDER_DISABLE_VALUES = (
    DEFENDER_ALWAYS_ANOMALOUS_VALUES | DEFENDER_DIRECTION_DEPENDENT_VALUES
)


# Defender-family signals that describe a write to Defender's *own*
# configuration/service registry.  When the writer IS the verified Defender
# engine, these are self-writes (boot/update bookkeeping, enabling tamper
# protection, SpyNet/sample-submission consent) — the inverse of tamper — so
# they must not score.  ``ransomguard_service_tamper`` is deliberately absent:
# Defender never edits *our* service, so a hit there is always suspicious.
_DEFENDER_FAMILY_SIGNALS = frozenset({
    "defender_service_tamper", "defender_filter_tamper", "mdatp_sense_tamper",
    "defender_settings_tamper", "defender_policy_tamper",
})


def _classify(key_path_lc: str):
    for needle, sig in _PATTERNS:
        if needle in key_path_lc:
            return sig
    return ("registry_other", 1, Severity.LOW, "Watched-key write")


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

        # Is the writer the verified Defender engine?  (Image-path verified, so a
        # fake "MsMpEng.exe" elsewhere won't match.)  Defender writing its *own*
        # config/service keys is normally self-config, not tamper — the old rule
        # judged only key+value and fired HIGH on those, the dominant source of
        # score inflation on an idle box.  But "Defender actor ⇒ always benign"
        # is too strong: a value-NAME that itself means *weakening* protection is
        # not something the engine writes in normal operation, so we still flag
        # it (see DEFENDER_ALWAYS_ANOMALOUS_VALUES).
        is_def_actor = (sig_name in _DEFENDER_FAMILY_SIGNALS
                        and is_trusted_defender_actor(pid))
        value_lc = value.lower()

        if sig_name == "defender_settings_tamper":
            # Settings key fires on *every* write; the driver hands us the value
            # NAME (evt.Extra) but not the DWORD.  Decide on the name:
            if value_lc in DEFENDER_ALWAYS_ANOMALOUS_VALUES:
                if is_def_actor:
                    # Verified engine writing a protection-disabling value to its
                    # own config — anomalous even from Defender (injection /
                    # impersonation is a known EDR-evasion path).  Keep a weak,
                    # non-zero signal.  ``defender_self_disable`` is exempt from
                    # actor-trust suppression (see actor_trust) so it still
                    # scores despite the trusted PID.
                    sig_name = "defender_self_disable"
                    weight = 15
                    severity = Severity.MEDIUM
                    base_msg = ("Defender engine wrote a protection-disabling "
                                "value to its own config (anomalous — possible "
                                "injection/impersonation)")
                # non-Defender actor → stays defender_settings_tamper (55/HIGH)
            elif value_lc in DEFENDER_DIRECTION_DEPENDENT_VALUES:
                if is_def_actor:
                    # Defender writes these in the enabling direction constantly;
                    # without the DWORD we can't tell, so trust the engine here.
                    sig_name = "defender_self_write"
                    weight = 1
                    severity = Severity.LOW
                    base_msg = "Defender wrote its own configuration (self-write)"
                # non-Defender actor → stays defender_settings_tamper (55/HIGH)
            else:
                # Not a protection control at all (signature/telemetry
                # bookkeeping, e.g. SignatureUpdatePending) → low breadcrumb.
                sig_name = "defender_settings_write"
                weight = 1
                severity = Severity.LOW
                base_msg = "Write to Windows Defender configuration value"
        elif is_def_actor:
            # The other Defender-family keys (service/filter/sense/policy) carry
            # no per-value disambiguation; a verified-engine write is self-config.
            sig_name = "defender_self_write"
            weight = 1
            severity = Severity.LOW
            base_msg = "Defender wrote its own configuration (self-write)"

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
