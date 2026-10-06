# Pending user restart (development controller)

This is an **observational transition**, not a pre-exec launch gate. Preparing
and selecting never signal, stop, reload, or kickstart either service. The native
launcher and signed app are unchanged. The watchdog stays scheduled and active.
A spontaneous launchd restart can consume the candidate before a user clicks a
control; that is observed, not represented as user authorization or prevented.
The earlier launch-boundary counterexample refutes strict execution ordering,
not this protocol.

## Authority and publication

The implementation stays within the existing six-file control bundle:
`watchdog.py` contains the pending policy and commands; `restart_production.py`
blocks generic process rollback/restart while a pending receipt exists. No new
runtime module or change to `CONTROL_FILES` is required.

1. Install/verify the **new management bundle first**, without selecting a new
   application release or restarting services. See installation requirements.
2. `watchdog.py --prepare-pending CANDIDATE --expected-old-sha256 OLD
   --expected-new-sha256 NEW --approve` performs existing preflights, native
   bundle/loaded-job validation, and a complete live fallback snapshot. It writes
   `pending-user-restart.json` but leaves the selector unchanged. It retains exact
   old/new selector bytes and hashes, original file identities and modes, both
   plist records, original native process identities, the original terminal
   activation transaction, lock identity, refresh pin, and an absolute deadline.
3. Preparation adds only `pending_restart_sha256` to the existing terminal
   activation transaction (using its existing envelope and refresh fence). This
   is the watchdog's durable authority to resolve the immutable receipt. The
   receipt checksum alone is not authorization. Existing wrapper arguments need
   only their new control-refresh pin; no circular receipt/wrapper pin is needed.
4. `watchdog.py --select-pending --pending-restart-sha256 RECEIPT --approve`
   revalidates the receipt, transaction, refresh authority, revocations, original
   healthy native identities, and exact old selector identity before publishing
   candidate bytes under `control.lock`. It verifies the readback. Repeating the
   command with the already-selected exact candidate returns `already_selected`,
   without claiming it is running or initiating a restart.
5. The user operates supported **Restart WebUI / Restart Gateway** controls.
   Neither control is invoked by preparation or selection. The controller does
   not infer which action caused an observed process replacement.

All commands take `--base` and, for a sealed refreshed executor, the existing
`--control-refresh-sha256` pin. These are development interfaces, not installation
instructions or approval to invoke them against an existing service.

## Effective running state and watchdog

The native parent/child identity matcher classifies each role against the retained
old and new exact argv/executable/signature/birth/ownership contracts. Both mixed
states are observable: old Gateway/new WebUI and new Gateway/old WebUI. The
watchdog checks HTTP/assets against the **running WebUI**, and Gateway state/SHA
against the **running Gateway**. It never publishes a synthetic mixed manifest.
An unknown identity is blocked rather than guessed. A mixed state is not a claim
of release readiness, full API compatibility, or successful message delivery.

A healthy old pair remains `awaiting_user_restart`; a healthy mixed pair is
`transition`. A complete candidate snapshot is initially `candidate_observed`.
It becomes `verified` only after a subsequent stable identity observation spanning
`stable_seconds`, with full snapshot and candidate preflight checks. Readiness
proof includes deep health and served assets, not live messaging delivery.
The result is durable in `pending-user-restart-result.json`; the normal watchdog
result embeds it. Completion stops the pending deadline from later undoing a
verified selection, but subsequent observations still validate live identities.

Normal grace, shallow-failure counting, cooldown/backoff, and deep-health
`degraded` behavior remain active. Selection mismatch alone never increments
shallow liveness failure counts. A genuinely unhealthy, positively identified
old WebUI may be repaired only after CAS-restoring the old selector; otherwise
its watchdog repair would silently become a candidate cutover. A running new
WebUI can receive ordinary liveness repair only while new remains selected.
**An old rollback selector grants no permission to kill a serving new WebUI.**
Missing/foreign identity is fail-closed, including when it prevents automatic
repair. The pending observer itself never signals any process.

## Timeouts, rollback, crash handling

The default pending window is one hour; preparation accepts a positive finite
`--pending-timeout` up to one day. Expiry before verified completion, candidate
revocation, or `--rollback-selection --pending-restart-sha256 RECEIPT --approve`
CAS-restores the exact old selector after validating the fallback. A foreign
selector is never overwritten. This does not restore process state: already
running or admitted candidates may survive or appear later. The observer reports
`rollback_user_restart_required` for mixed/candidate processes after rollback.
User-owned restarts, not automatic pair termination, complete process recovery.

The lock covers cooperating controllers, not launchd's selector reader. A process
can change immediately after an identity check or execute a selector it read
before rollback. This protocol does not claim otherwise.

A prepare crash after the immutable receipt but before the transaction fence
leaves the old selector untouched and watchdog action blocked. An explicitly
pinned, approved selection retry may finish that fence only when the original
transaction and original live fallback still match. A crash after selector
publication is handled by observation, not legacy activation recovery. Generic
controller restart/return/recovery is refused while the pending receipt exists.
The receipt remains retained after completion/rollback; archival/retirement into
normal generic controller operation is a separately reviewed management action,
not an automatic deletion of rollback evidence.

## Installation requirements (not performed here)

- Use a **new sealed version directory** containing the same six runtime files
  and `control-receipt.json`, with freshly computed hashes and existing ownership,
  ancestor, inventory and mode checks. Do not overwrite a sealed installed version.
- Publish a fresh controls-refresh receipt and management wrappers through a
  reviewed crash-recoverable installer, preserving the original root receipt,
  original deployment/history and retained rollback records. Re-fence the current
  terminal activation transaction to the new refresh pin. Existing management
  wrappers already consume their refresh pin; the watchdog discovers the pending
  pin from that fenced transaction after preparation.
- Keep the signed app, root launcher bytes/inode/hash, launcher pin, plists,
  selected release, and current services unchanged during management installation.
  Never disable the watchdog or use the legacy machine-specific reseal script.
- Install before preparing a receipt: receipts bind their exact installed refresh
  pin. Replacing management again while pending requires explicit receipt/transaction
  migration, not silently reusing a receipt bound to an older executor.
- Separately verify actual supported UI controls consume the selected native
  route. In particular, the old WebUI's Gateway CLI bootstrap/environment and
  native-host-preserving restart are outside this controller-only patch. Fixture
  tests do not establish that live UI path or mixed application compatibility.

## Verification

Stdlib fixture suite (all temporary state must be redirected into an approved
scratch directory; no real application or production interpreter execution):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts/production_control \
  python3 -B -m unittest test_pending_user_restart test_restart_control \
  test_transaction_recovery test_control_refresh_runtime \
  test_production_launcher test_pending_restart_boundary -q
```

Coverage includes both independent restart orders, effective-old watchdog health,
selection-only timeout/rollback, spontaneous post-rollback candidate arrival,
readiness stability, foreign selector/receipt/transaction/plist/identity refusal,
prepare crash recovery, repeated selection, real shallow failure versus mere
selection mismatch, and no process authority gained by rollback. Native OS APIs
and service controls are fixture boundaries; no native app/launchd/UI restart or
live messaging test is claimed.
