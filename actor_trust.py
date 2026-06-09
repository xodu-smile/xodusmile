"""
Actor Trust
-----------
Classifies the *actor* (the process behind a signal) as a trusted Microsoft
system component or not.  This is the missing layer the scoring model lacked:
the score used to sum every signal's weight regardless of *who* produced it,
so normal OS housekeeping — Defender writing its own config on boot, the WMI
performance-counter library being rebuilt, Windows servicing churning temp
files — inflated the global score to CRITICAL on an idle machine.

The fix gates the *input to the score*, not the kill moment.  A signal whose
originating PID resolves to a trusted system actor contributes nothing to the
global score and cannot corroborate a heuristic against another PID.

Trust is decided by the *verified on-disk image path*, never the bare process
name.  Malware dropped as ``C:\\Temp\\MsMpEng.exe`` matches the name but not
the protected system root, so it is NOT trusted.  When the image path cannot
be resolved (process already exited, access denied) we fail closed → untrusted
→ scored normally.  That is the safe default: the cost of an unresolvable
benign actor is a little score noise, never a missed detection.

Why path verification is sufficient: the trusted roots (System32, the Defender
platform dir, WinSxS/servicing) are write-protected for non-TrustedInstaller
principals, and the named binaries (MsMpEng, TiWorker, …) run as PPL or
SYSTEM.  An attacker cannot place a file at one of those paths without already
owning the box, and cannot inject the real PPL binaries from user mode.
"""

from __future__ import annotations

import os
import threading
from typing import Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# Trust tiers.  The distinction matters because not every "system" process
# is equally safe to exempt from *file* scrutiny.
TRUST_NONE          = 0   # scored normally
TRUST_REGISTRY_ONLY = 1   # benign for registry/process housekeeping, but its
                          #   bulk file mutation is still scored (see below)
TRUST_FULL          = 2   # benign for everything, including file activity

# FULL-trust actors: their *normal* job genuinely includes heavy, benign file
# churn — Defender scanning, the component store / servicing rewriting files,
# the WMI performance-counter library being rebuilt.  Exempting their file
# activity is what stops that churn from inflating the score.  Membership here
# is necessary but not sufficient — the path must also sit under a TRUSTED_ROOT.
_FULL_TRUST_NAMES = frozenset({
    # Microsoft Defender antivirus platform (scans/signature updates =
    # legitimate heavy file churn).  NOTE: MpCmdRun is deliberately NOT here
    # — it's a documented LOLBIN, so it sits at REGISTRY_ONLY below.
    "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe",
    "securityhealthservice.exe", "smartscreen.exe",
    # Defender for Endpoint (MDATP) sensor components.  Live under
    # "...\\Windows Defender Advanced Threat Protection\\", which still
    # matches the "\\program files\\windows defender" root prefix below.
    # These are protected sensor processes, not general-purpose tools.
    "mssense.exe", "senseir.exe", "sensecncproxy.exe", "sensendr.exe",
    "sensetvm.exe",
    # Windows servicing / component store (TrustedInstaller chain)
    "trustedinstaller.exe", "tiworker.exe", "dism.exe",
    # WMI / performance-counter rebuild chain (WmiApRpl, lodctr/winmgmt).
    # NOTE: mofcomp is a LOLBIN → REGISTRY_ONLY below, not here.
    "wmiadap.exe", "wmiprvse.exe", "unsecapp.exe", "lodctr.exe",
    "winmgmt.exe",
})

# REGISTRY-ONLY-trust actors: svchost is the carrier for servicing / Windows
# Update / background maintenance, so its *registry & housekeeping* writes are
# benign — but svchost is also a fat target.  A service hijacked or injected
# into svchost runs as the real System32\svchost.exe and would inherit trust,
# so we deliberately do NOT extend that trust to bulk file mutation: a svchost
# that suddenly mass-encrypts/renames files is anomalous and must still score.
# (Lone benign deletes like the servicing cabXXXX.tmp are still neutralised by
# file_delete's correlation gate and the bridge's BURST_EXEMPT_PATHS entry.)
_REGISTRY_TRUST_NAMES = frozenset({
    "svchost.exe",
    # Known LOLBINs that legitimately touch the registry / their own config
    # but whose *file* writes we still want scored: MpCmdRun can be abused to
    # download/stage files (`-DownloadFile`) and mofcomp to drop WMI MOFs.
    # Registry/housekeeping stays exempt; bulk file mutation is scrutinised.
    # (MpCmdRun also stays in _DEFENDER_ACTOR_NAMES so its writes to Defender's
    # own config keys are still recognised as self-config, not tamper.)
    "mpcmdrun.exe", "mofcomp.exe",
})

# Any verified name in either tier passes the name half of the path+name check.
_TRUSTED_ACTOR_NAMES = _FULL_TRUST_NAMES | _REGISTRY_TRUST_NAMES

# Defender-family actors specifically.  Used to exempt Defender's own writes
# to its configuration/service registry (it touches those keys constantly on
# boot and signature update — that is the opposite of tamper).
_DEFENDER_ACTOR_NAMES = frozenset({
    "msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe",
    "mpcmdrun.exe", "securityhealthservice.exe",
    # Defender for Endpoint sensor — writes to its own \Sense service /
    # ATP config keys, which is self-config, not tamper.
    "mssense.exe", "senseir.exe", "sensecncproxy.exe", "sensendr.exe",
    "sensetvm.exe",
})

# Lower-cased path fragments an image must contain to count as system-trusted.
# These directories are not writable by ordinary principals, so a name match
# here cannot be spoofed without already controlling the machine.
_TRUSTED_ROOTS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\servicing\\",
    "\\windows\\winsxs\\",
    "\\program files\\windows defender",
    "\\program files (x86)\\windows defender",
    "\\programdata\\microsoft\\windows defender\\",
)


# Cache: pid -> (create_time, trust_tier, is_defender_trusted).
# create_time guards against PID reuse — if the process at this PID was
# created at a different time than we recorded, the entry is stale.
_cache: dict[int, Tuple[float, int, bool]] = {}
_cache_lock = threading.Lock()
_CACHE_CAP = 4096


def _resolve(pid: int) -> Tuple[int, bool]:
    """Return ``(trust_tier, is_defender_trusted)`` for ``pid``.

    Fails closed (``TRUST_NONE, False``) on any lookup error so an exited or
    inaccessible process is never silently trusted.
    """
    if not HAS_PSUTIL or pid <= 0:
        return (TRUST_NONE, False)
    try:
        proc = psutil.Process(pid)
        create_time = proc.create_time()
    except Exception:
        return (TRUST_NONE, False)

    with _cache_lock:
        cached = _cache.get(pid)
        if cached is not None and cached[0] == create_time:
            return (cached[1], cached[2])

    try:
        exe = proc.exe() or ""
    except Exception:
        # No path → cannot verify → untrusted.  Cache the miss so we don't
        # hammer psutil for the lifetime of an unresolvable process.
        with _cache_lock:
            _store(pid, create_time, TRUST_NONE, False)
        return (TRUST_NONE, False)

    path_lower = exe.lower()
    base = os.path.basename(path_lower)
    under_root = any(root in path_lower for root in _TRUSTED_ROOTS)

    if not under_root:
        tier = TRUST_NONE
    elif base in _FULL_TRUST_NAMES:
        tier = TRUST_FULL
    elif base in _REGISTRY_TRUST_NAMES:
        tier = TRUST_REGISTRY_ONLY
    else:
        tier = TRUST_NONE
    defender_trusted = under_root and base in _DEFENDER_ACTOR_NAMES

    with _cache_lock:
        _store(pid, create_time, tier, defender_trusted)
    return (tier, defender_trusted)


def _store(pid: int, create_time: float, tier: int, def_t: bool) -> None:
    # Caller holds _cache_lock.
    if len(_cache) >= _CACHE_CAP:
        _cache.clear()
    _cache[pid] = (create_time, tier, def_t)


def trust_tier(pid: int) -> int:
    """The trust tier of ``pid``: TRUST_NONE / TRUST_REGISTRY_ONLY / TRUST_FULL."""
    return _resolve(pid)[0]


def is_trusted_system_actor(pid: int) -> bool:
    """True if ``pid`` carries *any* system trust (full or registry-only).

    Note this is coarse — for scoring, prefer ``signal_actor_trusted`` which
    also weighs the signal kind so svchost's bulk file activity isn't trusted."""
    return _resolve(pid)[0] != TRUST_NONE


def is_trusted_defender_actor(pid: int) -> bool:
    """True if ``pid`` is the verified Microsoft Defender engine/service.

    Used to recognise Defender writing its *own* configuration/service
    registry — the inverse of tamper — so we don't flag it as an attack."""
    return _resolve(pid)[1]


def _pid_of_signal(sig) -> Optional[int]:
    meta = getattr(sig, "metadata", None) or {}
    for key in ("pid", "ProcessId", "process_id", "child_pid"):
        val = meta.get(key)
        if isinstance(val, int) and val > 0:
            return val
    return None


# File-mutation signal names.  A REGISTRY_ONLY-trust actor (svchost) is NOT
# exempted for these — only FULL-trust actors are — so a service-hosted or
# injected svchost that mass-encrypts/renames/deletes still raises the score.
# Sourced from the scoring engine's encryption set so the two stay in sync.
try:
    from scoring import ENCRYPTION_SIGNAL_NAMES as _ENC
except Exception:                                   # pragma: no cover
    _ENC = frozenset()
_FILE_ACTIVITY_SIGNALS = frozenset(_ENC | {"file_delete"})

# Signals that must score even when the actor is otherwise FULL-trust.  These
# describe the trusted actor doing something it never does in normal operation
# — e.g. the verified Defender engine writing a protection-*disabling* value to
# its own config.  Injecting into / impersonating a PPL like MsMpEng to weaken
# protection from "inside" is a documented EDR-evasion technique, so blanket-
# exempting every signal carrying that PID would be the one blind spot an
# attacker would aim for.  The detector only raises these for genuinely
# anomalous self-activity, so they stay rare.
_NEVER_ACTOR_EXEMPT = frozenset({
    "defender_self_disable",
})


def signal_actor_trusted(sig) -> bool:
    """Classifier for the ScoringEngine: should this signal be exempted from
    the score because of *who* produced it?

    - Signals in ``_NEVER_ACTOR_EXEMPT`` → never exempt (trusted actor behaving
      anomalously, e.g. Defender disabling its own protection).
    - FULL-trust actor (Defender, servicing, WMI/perf) → otherwise always exempt.
    - REGISTRY_ONLY-trust actor (svchost) → exempt only for non-file signals;
      its bulk file mutation is scored so svchost-hosted ransomware is caught.
    - PID-less signals (e.g. canary) are never exempt — we can't attribute
      them, so they score normally.
    """
    if getattr(sig, "name", None) in _NEVER_ACTOR_EXEMPT:
        return False
    pid = _pid_of_signal(sig)
    if pid is None:
        return False
    tier, _ = _resolve(pid)
    if tier >= TRUST_FULL:
        return True
    if tier == TRUST_REGISTRY_ONLY:
        return getattr(sig, "name", None) not in _FILE_ACTIVITY_SIGNALS
    return False
