# Resilient local Hermes production control

## User story and proven failure

A healthy WebUI must not be stopped only to discover its replacement is forbidden
because someone committed an unrelated edit in an Agent checkout. Restart is not
deployment, and moving development HEAD must not change production launchability.

The September 21 incident was reproduced with the **actual legacy validator**:
old approval + current checkout refused Agent and WebUI; changing only the Agent
commit in the manifest made both pass. The failure occurred before application
execution, not in the title-policy code.

Local incident evidence (America/Chicago):

- 23:37:31: Agent HEAD advanced from `afbe045531afd28fb61c702eee10561ecbf56302`
  to `0a70319b64d017b7ad7b7d31bdc7d12f867705b4` (one title-tag insertion).
- 23:40:27: WebUI accepted `/api/webui/restart`, then interrupted the healthy PID.
- 37 startup refusals followed: `agent: HEAD differs from approved release`.
- 23:44:34: watchdog retried the same deterministically blocked launch path.
- 23:46:48: external repair advanced the Agent pin in the manifest.
- 23:47:04: replacement started; 23:47:09 first observed successful request.
- Separate HTTP bug: unread `{}` restart body contaminated the next keepalive
  request into `{}POST`, returning 501. Regression reproduced before patch.

Counterfactual: preflight before SIGINT would have rejected the restart while
preserving the healthy WebUI. Frozen releases also remove mutable checkout HEAD
from routine startup authorization entirely.

The running gateway still reported `afbe0455` after the repair; editing a manifest
did not update its process. The preserved fallback uses that observed running
version, not the repaired checkout's HEAD. WebUI source: `9f51c03e`.

## Authority and design

- `production-release.json` schema 2 selects an explicit Agent/WebUI pair.
- Sources, private Python distribution, and installed packages are copied into
  separate versioned release directories. Startup verifies inventories offline.
- `.git` metadata is not launch authority. Unexpected source files, import
  shadows, bytecode, dependency changes, or escaping symlinks fail preflight.
- Source `.env` is not bundled. Credentials/state remain under Hermes home.
- Python safe-path mode excludes the writable state cwd from module discovery;
  approved source directories are explicit. User site-packages are disabled.
- No network install, Git fetch, branch reset, moving tag, or auto-blessing during
  startup. Release paths are retained and are not an auto-update channel.
- launchd remains sole supervisor. CLI manager markers prevent generic install
  and refresh from replacing managed definitions. WebUI restart checks local
  manager metadata before acknowledgement or SIGINT.
- One flock serializes watchdog/restart. Preflight occurs before interruption.
- Candidate activation first proves the old live pair healthy. Old manifest and
  exact plist bytes are saved durably before candidate publication. A fresh
  watchdog/controller reconciles an interrupted transaction.
- A rollback consumes one durable attempt before acting; failed/interrupted
  rollback is terminal, not an infinite loop. No known-good approval expiry.
- Informational journal I/O failure cannot prevent rollback. Transaction backup
  persistence remains mandatory before destructive actions.
- `revoked-releases.json` may revoke release IDs or service-content digests;
  malformed policy fails closed. Revocation is checked on launch and recovery.
- Shallow process/HTTP failure drives bounded watchdog restarts. Deep dependency
  failures report degraded without blindly killing a serving WebUI. New-PID
  grace and persisted cooldown/backoff prevent restart storms.

## Tools

All scripts here are standard-library control-plane programs. Application imports
are checked using the selected release interpreter with temporary isolated state.

- `release_build.py`: offline preparation only. Pass exact source refs, source
  venv executable, state dir, environment path, output dir, verification note.
  Do not resolve a venv interpreter symlink before querying its site-packages.
- `canary.py MANIFEST --output RECEIPT --test-api`: actual frozen WebUI under
  disposable launchd label/HOME/loopback port, no production credentials or
  messaging adapters. Cold start, SIGTERM, SIGKILL, API refusal-preserves-PID,
  accepted API restart, deep health, five static-file hashes, cleanup.
- `live_control_test.py RECEIPT`: real launchd, explicitly synthetic services;
  routine restart, bad candidate rollback, tamper refusal before interruption.
- `install_controls.py`: one-time schema-1 to schema-2 migration. Versioned control
  bundle, dual-schema bridge, atomic pointer publication. Does not stop or start
  services. An interrupted installation retains a compatible launcher.
- `prepare_cutover.py`: stages explicit one-shot launchd cutover; never loads it.
  Candidate may replace cached launchd Python/cwd/env via explicit `--reload`.
  Preserve the old definitions until verification so rollback remains exact.
- `experiments/verity_identity/refresh_production_controls.py`: separate controls-only
  native repair, preserving the signed app and stable launcher. Its three-wrapper
  publication, schema-2 transaction fence, exact return and dedicated restoration
  are described in `experiments/verity_identity/CONTROL-REFRESH.md`. This path is
  offline-verified, not installed or approved for activation.

## Local operating runbook

Installed base: `~/.hermes/maintenance`. Read-only check:

```sh
python3 -B ~/.hermes/maintenance/restart_production.py
```

Interactive routine restart (both services; intentionally disruptive):

```sh
python3 -B ~/.hermes/maintenance/restart_production.py --restart
# Type: restart
```

Prefer a preserved release interpreter rather than Homebrew's moving executable.
Never invoke `--yes` as a child of the service being restarted: it requires PID 1
as parent. An explicitly authorized independent launchd job is the automation
path. Do not bootstrap/kickstart a staged cutover without the user's approval.
`RunAtLoad=false` and `KeepAlive=false` keep it one-shot and unarmed when staged.

Candidate promotion is `--restart --activate /absolute/candidate.json`; add
`--reload` only for explicit launchd-definition migration. A normal kickstart
uses cached definitions and **does not reread an edited plist**.

Read back after cutover:

1. `restart-result.json` has matching operation ID and `verified` status.
2. Both launchd PIDs changed; WebUI listener is its launchd PID.
3. Gateway child belongs to its launchd wrapper and reports expected code SHA.
4. Shallow/deep JSON health pass, server timestamp is fresh, five served hashes
   match the selected snapshot.
5. Persisted and loaded argv/cwd match. `activation-transaction.json` is terminal.
6. Verify actual messaging separately; health is **not** end-to-end delivery proof.

`rolled_back` means candidate failed but prior pair passed recovery checks.
`rollback_failed` or corrupt transaction means stop automatic attempts, diagnose
logs, inspect actual PIDs/state, and explicitly reconcile. Do not delete the
transaction merely to bypass refusal. A whole-disk I/O outage cannot be repaired
by a source rollback; repair storage first. Never reset dirty checkouts.

Keep the selected snapshot, prior known-good snapshot, and control interpreter
snapshot. Never prune a runtime still referenced by loaded plists, manager
preflight, watchdog wrappers, manifest, or transaction backup. Do not update
source or packages in-place inside a release directory.

## Exact return to the retained legacy baseline (new control version)

`--restart --reload --return-baseline INSTALL_RECEIPT_SHA256` is distinct from
activation and incomplete-transaction recovery; it excludes `--activate`.
The argument is the separately reviewed SHA-256 of the **exact bytes** of
`BASE/native-install-receipt.json`, not a filename or a self-reported checksum.
It requires the installed receipt's terminal `installed` phase, current terminal
activation transaction, and the exact native candidate recorded by that stage
(semantic candidate digest permits noncanonical current JSON). No arbitrary
backup file, command, destination, label or state-directory override is accepted.

The controller verifies the receipt checksum, base/home, embedded stage hashes,
retained manifest/plists and wrapper baseline inventory, installed version/path,
five control hashes/modes and installed wrapper bytes/modes. Both selections
must pass existing revocation and preflight checks; both definitions are validated
before publication, and the current native pair must pass the existing snapshot.
Canonical paths, ownership/modes, file and ancestor identity, existing shared lock,
and input stability are checked before publication. All cooperating control-plane
writers must honor `control.lock`; this is not containment against a malicious
same-UID process that can replace owned files between system calls.

The existing transaction saves the **current exact native manifest and plists**
as a fresh verified-live fallback, with `operation=return-retained-baseline` and
the approved receipt digest. Original legacy bytes remain separately retained in
the unchanged install receipt. Atomic per-file publication bypasses override
merging and serialization; successful readiness is followed by exact byte and
owner/mode readback. There is no multi-file atomic rename: the durable prepared
transaction covers interruption between publications. Failed/interrupted returns
use existing one-attempt recovery to native; failed recovery is terminal. A
prepublication race detected after durable preparation may leave a prepared
transaction without changing the selection: do not edit its phase; use separately
approved ordinary recovery. Informational receipts are not recovery authority.

`--yes` still requires a directly launchd-owned independent controller; otherwise
interactive confirmation is required. Neither flag grants operator approval.
Without an additional pin, this operation still requires the executing controller
in the installed receipt's exact control version. **Explicit contract change:**
`--return-controller-sha256 DESCRIPTOR_SHA256` separates executor provenance from
installed artifact provenance for an already-installed v1 deployment. It is valid
only together with `--return-baseline INSTALL_RECEIPT_SHA256 --restart --reload`.
Neither digest is inferred from disk: both are independently reviewed operator
inputs. The descriptor is deployment provenance, not self-trusted authority.

The executing file must be the canonical
`BASE/return-control-versions/NAME/restart_production.py`, where NAME contains only
ASCII letters, digits, underscores and hyphens. Retain exactly these five files:
`restart_production.py`, `approved_restart_job.py`, `production_launcher.py`,
`native_identity.py`, `watchdog.py`, plus `return-controller.json`. The directory
must be 0555; every file, including the descriptor, must be 0444, owned by the
operator, with safe canonical nonsymlink ancestors. Run with `-B` to avoid creating
bytecode or extra directory members. The descriptor has exactly these fields:

```json
{
  "schema_version": 1,
  "base": "<canonical BASE>",
  "executor": "<canonical BASE>/return-control-versions/<NAME>/restart_production.py",
  "installed_version": "<original receipt report.final_control_version>",
  "install_receipt_sha256": "<SHA-256 of exact original install receipt bytes>",
  "control_sha256": {
    "restart_production.py": "<SHA-256 of separately retained file>",
    "approved_restart_job.py": "<SHA-256 of separately retained file>",
    "production_launcher.py": "<SHA-256 of separately retained file>",
    "native_identity.py": "<SHA-256 of separately retained file>",
    "watchdog.py": "<SHA-256 of separately retained file>"
  }
}
```

The optional CLI pin is the SHA-256 of the descriptor's **exact bytes**. The
transaction records it as `return_controller_sha256`, alongside the unchanged
`baseline_sha256`. Descriptor, all five executor files, identities/modes and exact
membership are rechecked across preflight, journal and durable-prepared boundaries
before target publication. Original receipt, installed controls, wrappers,
candidate, shared lock, revocation, health and recovery validation remain required.

A separately reviewed deployment can stage only this six-file return bundle; it
must never modify installed v1 controls, receipt, app, wrappers or plists to make
the new executor match. Existing installations do not acquire this operation from
a checkout edit. The first-install-only installer is not an upgrade path. This is
not an app upgrade, automatic continuation mechanism, or general installer.
No installation, cutover, service interruption, permission grant, wrapper restore,
artifact removal, or same-session autonomous resume is proved by offline tests.

## Exact return after a one-hop immutable upgrade

The optional `--return-upgrade-sha256 UPGRADE_RECEIPT_SHA256` is a distinct
explicit deployment-provenance route. It requires
`--return-baseline INSTALL_RECEIPT_SHA256 --restart --reload`, excludes
`--activate`, and cannot combine with `--return-controller-sha256`. Both pins
are independently approved digests of exact receipt bytes, never inferred from
current files. Always supply the actual `--base` on a versioned executor.

The root install receipt remains authority for the original legacy selector and
plist bytes. The committed `native-upgrade-receipt.json` binds the currently
installed v2 deployment: root lineage, both retained stages and candidate hashes,
original/new reports, control inventories and exact membership, regenerated
version-bound wrappers, current candidate, both app trees and the retained v1
app inode. The executing controller must actually reside in that v2 immutable
control directory; a checkout or separate return executor cannot stand in for it.
No installer or stager module is imported by the installed controller. Both
retained stages remain required. Existing no-upgrade behavior stays unchanged.

The normal signature, native readiness, preflight, revocation and lock checks
still apply. File/directory provenance is rechecked around preflight, journal
intent and durable preparation before selection changes. The real return
transaction records `upgrade_sha256` and `baseline_sha256`, then uses the existing
exact-byte return and bounded native fallback. A failed return is not the
verified proof required by the installer's post-return wrapper restore.

`test_upgrade_return_composition.py` executes fixture first install, fresh stage,
upgrade, native activation, exact return and original-wrapper restore through
actual staged/installed Python modules. The resulting transaction, not a
synthesized future receipt, supplies both pins. OS/signature/health/dependency
observations remain adapters; this is not launchd or maintenance admission proof.
Parent frozen aggregate replay passed 131 tests on both Python 3.11.16 and 3.14.7
with seven subprocess/native/compiler cases explicitly excluded. The same return
success test fails meaningfully against the old controller's
`Wrong installed control identity` refusal on both ABIs. This is a demonstrated
old capability boundary; the new explicit upgrade pin is an additional input,
not an identical-input security-policy bypass. Focused source-only review
`deleg_66b6b131` is bounded-clear, and the parent matched the reviewed frozen
source to the committed runtime/tests. This closes the offline return-integration
gate only; it does not establish live exact return or maintenance launch exclusion.

## Native gateway timestamp-wrapper identity

Native readiness normally binds a direct service child. For the Agent only, it also
recognizes the exact selected command below when the gateway-state PID is not the
native host's direct child:

```text
PYTHON -m hermes_cli.stderr_timestamp --error-log ABSOLUTE_LOG -- PYTHON -m hermes_cli.main gateway run --external-supervisor
```

The wrapper must be the gateway's direct parent and the native host's direct child.
Both Python executable spellings must match the selected command, and each observed
executable must match its resolved path. Host, wrapper and gateway retain exact
PID/UID/argv/birth checks, chronological birth ordering, restart freshness and
running-host signature validation. Unknown wrappers, extra hops and extra arguments
are refused; this is not a general descendant search. The returned Agent identity
includes `wrapper`, so snapshot reobservation and readiness stability cover it without
changing the direct WebUI identity shape.

Independent frozen-source replay passed 71 offline native, restart, migration,
transaction-recovery and retained-return tests on Python 3.11.16 and 3.14.7. Both new
wrapper invariant methods failed against the unchanged old validator on each ABI
with `degraded != healthy`, then passed with the repair. Four explicitly excluded
tests require a subprocess probe, compilation or native execution. HOME/state were
isolated and pre-import host/network/application guards recorded no violations.
Ruff and `git diff --check` passed. This is fixture evidence, not live acceptance:
installed v1 remains unchanged and failed its first supervised trial. Activation,
watchdog and exact-return execution must all use a supported corrected control
version before retrying; replacing only the trial executor leaves stale supervision.

## Verification and limits

The separately pinned executor checkpoint passed 56 hermetic return, migration,
restart and transaction-recovery tests on both Python 3.11.16 and 3.14.7, including
an independent parent replay from a hash-frozen copy with isolated HOME/state and
pre-import subprocess/native/network/application tripwires. One real-interpreter
preflight test was deliberately excluded; native/compiler/live suites were not
collected. Two new invariant methods cover copied-controller execution, exact
return, bounded failure/recovery and provenance changes before publication. The
original controller's `Wrong installed control identity` refusal demonstrates the
old capability boundary, not an identical-input red/green regression: the new
explicit descriptor pin is an additional authorization input. Three existing Ruff
encoding findings were unchanged; no new lint findings were introduced. These
checks do not prove real launchd execution or installation. Focused source review
and deployment readback remain separate from this test checkpoint.

Focused lifecycle suites and hermetic fault tests are required before install.
Fault coverage includes cutover writes/kickstarts interrupted with BaseException,
concurrent locks, corrupt manifest/transaction/policy, revoked fallback, failed
rollback with no retry loop, journal I/O failure, request framing, dependency
preflight, import shadowing, and exact installed-file hash read-back.

Canaries prove real process recovery, not a full host reboot or messaging delivery.
This is still one Mac, one disk, one user launchd domain. Hardware loss, macOS
failure, unavailable network/model providers, incompatible state migrations, and
credential expiry are not solved by restart control. Automatic source rollback
must not be used for an incompatible state migration without a state backup and
an explicit migration/recovery plan. No responsible operator can promise this
single-host deployment will never fail.
