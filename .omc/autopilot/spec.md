# Autopilot Spec — RansomGuard EDR improvements

## Goal (from user)
Improve detection, prevent false detection, improve admin UI, add "something good",
Windows-only → write tests but do NOT run them, update README + docs.

## Findings (existing codebase is mature)
- Strong FP prevention already: `actor_trust.py` (3-tier path-verified trust), scoring
  correlation gating (`CORRELATION_GATED_NAMES`), `mass_io` noise paths.
- Gaps:
  1. **Detection gap**: no ransom-note-drop detector (a hallmark, often the first
     visible indicator). No way for an admin to extend trust at runtime.
  2. **False-positive gap**: `mass_io.high_entropy_write` fires on *natively* high-
     entropy user files (.mp3/.mp4/.avi/.mov/.mkv/.flac and archives whose magic
     isn't in the table) because they're in TARGET_EXTENSIONS and have no magic match.
     A legit re-save of these triggers a (benign) MEDIUM signal. Damage-verify already
     skips these exts (`incident_report._HIGH_ENTROPY_SKIP_EXTS`) but the *detector* does not.
  3. **Admin UI gap**: dashboard is consumer-grade (traffic light). No responder-mode
     control, no allowlist management, no per-PID threat breakdown, no system health,
     no standardized threat taxonomy.

## Deliverables
### New modules
- `attack_map.py` — MITRE ATT&CK technique tagging for every signal ("something good").
- `allowlist.py` — operator-managed runtime allowlist (process name / path prefix),
  JSON-persisted, thread-safe. Composes into the scoring trust classifier AND the
  responder never-kill check. Both FP-prevention and an admin feature.
- `detectors/ransom_note.py` — detects ransom-note file drops; requires multi-directory
  spread for the CRITICAL tier (low FP). Canary cross-boost like mass_io.

### Edits
- `scoring.py` — register `ransom_note_dropped`/`ransom_note_spread` in
  ENCRYPTION_SIGNAL_NAMES so notes corroborate.
- `detectors/mass_io.py` — exclude natively-high-entropy formats from the entropy heuristic.
- `agent.py` — wire allowlist into trust classifier + responder; add ransom-note detector;
  add admin methods (set_responder_mode, threat_breakdown, health); track start time.
- `responder.py` — consult allowlist in never-kill; `set_mode()`.
- `dashboard/app.py` — admin endpoints: health, mode, allowlist CRUD, threats.
- `dashboard/templates/index.html` — collapsible Administrator panel (health, mode
  switch, allowlist editor, per-PID threat table with ATT&CK tags).
- `incident_report.py` — add an ATT&CK technique line to reports.

### Tests (Windows-targeted; do NOT run this pass)
pytest suite + conftest + pytest.ini: scoring, actor_trust, mass_io (FP fix),
ransom_note, allowlist, attack_map, responder, dashboard_api, incident_report.

### Docs
README.md, README.en.md, docs/WIKI.ko.md, docs/WIKI.en.md, new docs/ADMIN_GUIDE.md.

## Constraints
- Match existing style: bilingual KO/EN comments, dataclasses, frozensets, threading,
  fail-closed trust. No new heavy deps. Keep detection semantics conservative (no new FP).
