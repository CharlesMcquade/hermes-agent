# Schema-2 native cutover: BLOCKED, unarmed offline recipe

**Not cutover-ready. Do not submit a job.** The old activation interface cannot
perform a byte-exact post-success return; `test_production_cutover_recipe.py`
continues to prove that unsupported inverse. The source controller now adds the
explicit retained-baseline operation below, verified only with offline fixtures.
It requires a **new installed control version and matched stage/install provenance**;
existing installed controls are unchanged. No installed artifact, production
selection, service, signature or permission was changed by this implementation.
Reliable autonomous same-WebUI-session resume and all permission/readiness gates
remain independent requirements; passing these tests is not permission to cut over.

## Scope and gates

Read `PRODUCTION-READINESS.md`, `PRODUCTION-STAGING.md`, `PRODUCTION-INSTALL.md`
and `scripts/production_control/README.md` first. Earlier lab continuity and
migration evidence is not production readiness. Permission limitations, final
identity continuity, actual descendant checks, messaging, logout/login and reboot
remain separately gated. No rehearsal authorizes a production interruption.

The operator's original stable-identity plan has now been reviewed, including its
rollback section: preserve exact definitions, manifest, runtime, controls and
receipts; use bounded recovery without TCC changes or state-schema reversal.
Reconcile that plan and readiness's remaining-gates matrix before declaring readiness. This document
is parameterized; store resolved production paths, hashes and approval in a
private gitignored local receipt, never in tracked examples.

## Exact matched path set (no PATH lookup, no old prepare_cutover)

Let `STAGE` be the retained, verified native stage, `REPORT` its
`stage-report.json`, `BASE = REPORT.final_base`,
`VERSION = REPORT.final_control_version`, and
`PYTHON = REPORT.bootstrap_python`. Use these exact strings, not another Python
ABI merely because it passes tests. Let `CANDIDATE` be the absolute canonical
`STAGE/candidate-release.json`, whose SHA-256 must equal
`REPORT.candidate_sha256`. Installation does not copy that file into BASE.

The independent job's controller is exactly
`VERSION/approved_restart_job.py`; its sibling imports must resolve to the same
version's `restart_production.py`, `production_launcher.py`, `native_identity.py`
and `watchdog.py`. Never execute a mutable checkout copy or use
`prepare_cutover.py` (it synthesizes legacy Python overrides). Never use the
old schema-1 installer. The installed stable wrappers in BASE point to VERSION;
they are not interchangeable with arbitrary source scripts.

Before approval/submission, a reviewed local readback must establish:

- Canonical absolute paths, expected owners/modes, safe ancestors, existing safe
  `BASE/control.lock`; VERSION is exactly `BASE/control-versions/CONTROL_ID`.
- Valid install receipt checksum/phase and stage report; all five installed
  control bytes and control receipt match `REPORT.control_sha256`; four wrappers
  match staged bytes/modes and installed receipt. Do not silently repair drift.
- Installed `REPORT.final_bundle` matches candidate inventory, strict leaf-pinned
  signature and signed settings. Settings base equals BASE, bootstrap Python
  equals PYTHON, stable launcher equals `BASE/production_launcher.py`, launcher
  hash agrees with the wrapper, and signed bootstrap environment is unchanged.
- Both retained legacy plist argv values equal
  `[PYTHON, BASE/production_launcher.py, role]`; source/runtime selection is
  unchanged, and each native override equals the staged definition. Validate
  both definitions with the matched Controller and native validation, not
  legacy argv assertions. Preserve Program removal only for the forward path.
- Byte-exact original manifest, binary/XML plist bytes, wrapper bytes/modes/owners
  remain in the stage and install receipt, separately from the mutable activation
  journal. Record/check their hashes before and after every attempt. A second
  transaction overwrites the active journal's original backup.
- Static inventories are NOT CLI preflight: preflight imports application modules
  and may read real state. Only run real preflight in an explicitly approved
  scope. Fixture preflight and signature adapters are not real-artifact proof.

## Independent one-shot job, UNARMED

The following pure function builds an in-memory plist only. It does not validate
installed bytes, grant approval, write a plist, load a job or execute a controller.
Its behavior is exercised by the offline test. `PRIVATE_JOB` is a new private
canonical directory outside auto-loaded LaunchAgents/LaunchDaemons directories;
prepare it only under the separately agreed operator scope. Keep the resulting
plist outside those auto-load directories. `Disabled=true`, `RunAtLoad=false`,
`KeepAlive=false`; no calendar, interval, socket, queue or path triggers.

```python
from pathlib import Path
import re


def unarmed_job(report, candidate, private_job):
    base = Path(report["final_base"])
    version = Path(report["final_control_version"])
    python = Path(report["bootstrap_python"])
    candidate, private_job = Path(candidate), Path(private_job)
    for path in (base, version, python, candidate, private_job):
        if not path.is_absolute() or path != path.resolve():
            raise ValueError("Explicit canonical absolute paths required")
    if (version.parent != base / "control-versions"
            or not re.fullmatch(r"[A-Za-z0-9_-]+", version.name)):
        raise ValueError("Controller version must match the installed receipt")
    return {
        "Label": "com.verity.production-cutover-once",
        "ProgramArguments": [str(python), "-B",
                             str(version / "approved_restart_job.py"),
                             "--base", str(base), "--restart", "--yes",
                             "--activate", str(candidate), "--reload"],
        "WorkingDirectory": str(base),
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                                 "PYTHONNOUSERSITE": "1",
                                 "PYTHONDONTWRITEBYTECODE": "1"},
        "Disabled": True,
        "RunAtLoad": False,
        "KeepAlive": False,
        "AbandonProcessGroup": False,
        "StandardOutPath": str(private_job / "stdout.log"),
        "StandardErrorPath": str(private_job / "stderr.log"),
    }
```

`ProgramArguments` is a literal array, not shell syntax: do not use `sh -c`,
`nohup`, the native service host, a gateway/WebUI worker, or a shell trampoline.
The controller must be directly launchd-owned (PPID 1), separate from both service
jobs it will interrupt. The one-shot must not share their labels or lifecycle.
The reviewed environment must also supply any required explicit HOME/TMPDIR/state
paths from the local receipt; never inherit credentials or PYTHONPATH. Their
production validity has not been established by this pure template test.

**Approval boundary:** the operator subsequently authorized autonomous cutover
conditional on a verified method to resume the initiating WebUI session. That
condition and all readiness gates remain unsatisfied. Before consuming that
authority, bind the exact candidate digest, matched installed controller and
interpreter, labels, user launchd domain, reload scope, recovery limits and
one-shot operation in its durable receipt. Install/test approval and `--yes`
alone are not submission authorization. Only a reviewed step satisfying those
conditions may arm, submit and start this one-shot. No submission/enable/
kickstart command is supplied while the return path is blocked. Do not test this
job against real services as a shortcut. There is no proven global wall-clock
limit for the operation: readiness polling and host commands have timeouts, but
an external forced kill can interrupt recovery; never claim otherwise.

## Readback after a separately authorized future cutover

Read the exact operation's result AND durable `activation-transaction.json`, not
just process exit status. `verified` is native success; `rolled_back` is failed
activation with successful recovery, not successful cutover; `rollback_failed`
is a stop requiring manual reconciliation. Missing/ambiguous evidence is unknown.

Verify selection against candidate semantics (the controller reserializes JSON),
persisted definitions against staged native definitions, and actual loaded argv
and cwd for BOTH jobs. Native roots must have candidate host executable/argv,
expected UID/PPID/birth identity and validated signature. Verify selected Python
children, gateway ownership/state, WebUI listener descendants, fresh health and
served-asset hashes using native-aware `Controller.snapshot` and its identity
checks. A native root PID is not the Python child PID. Separately verify no stale
legacy or orphan descendants and no continuing one-shot dependency before its
approved cleanup. Actual permissions and messaging require their own consented
checks; healthy HTTP is not proof of either. These are future live checks, not
results of this offline task.

## Recovery: failed/incomplete transaction versus successful cutover

1. **Failed activation:** ordinary exceptions after mutation invoke the existing
   one-attempt `recover_locked` path. For `rolled_back`, compare original manifest
   and both plist bytes, then loaded legacy definitions/health. Native app, controls
   and wrappers stay intact. Installer wrapper restore is a separate operation.
2. **Interrupted prepared transaction:** under the shared lock, the matched
   controller's restart entry first invokes recovery. A supplied candidate is NOT
   activated in that invocation. Any future recovery invocation needs explicit
   restart approval and the same independent owner. Recovery uses the transaction's
   retained original bytes and checks revocation/preflight before restoring. It
   durably consumes the sole attempt before restoration. `rollback_started` or
   `rollback_failed` is NOT retry permission; stop for reconciliation. Never edit
   journal phases/checksums to force another attempt.
3. **Terminal verified transaction:** recovery returns `None`; restart proceeds
   to a new transaction on the current selection. Restart without `--activate`
   restarts native services, not legacy. An original legacy manifest alone fails
   native-plist validation. Adding legacy argv/cwd overrides can verify, but leaves
   native association/process-group policy, omits original Program, reserializes
   plist/manifest bytes and adds overrides absent from the original manifest.
   This is NOT the required return-to-legacy procedure. Do not execute it.
4. **Installer restore is not selection rollback:** it restores wrappers only,
   requires exact original selection/plists and affirmative no-native-dependency
   proof. It rejects the post-success native selection and the nonexact inverse.
   Never restore wrappers under a native selection, remove native artifacts,
   hand-write original plists while native jobs are live, or overwrite the current
   transaction with an older backup.

## Exact retained-baseline contract (source implemented; installation still gated)

The existing controller transaction path now accepts an explicit, separately
approved **return-to-retained-baseline** operation, not a phase-editing script.
Its literal argument suffix is `--restart --yes --reload --return-baseline
INSTALL_RECEIPT_SHA256`, where the digest pins the exact installed receipt file
bytes at `BASE/native-install-receipt.json`. It excludes `--activate`; the direct
launchd-owned `--yes` guard is unchanged. This is not an armed job recipe.

The embedded stage report's selected-manifest, rollback-inventory, candidate and
control hashes are checked, along with the installed receipt envelope, phase,
base/home, version identity, five installed control files, control receipt, and
four wrappers. The current native selection must equal that installed stage's
candidate semantically; the retained target contains no native host or overrides.
Only original manifest/plist destinations are accepted. The receipt must be
externally pinned by separately reviewed SHA-256, not trusted because it can
checksum itself. The stage and original install receipt remain independently
retained; no prior activation journal is used as baseline authorization.

Contract implemented:

- Accept an identified/checksummed retained baseline (original manifest AND exact
  plist bytes), validate schema/paths/labels/state/revocation and installed receipt
  provenance. Require a terminal current transaction and explicit reload/approval.
- Under the same control lock, validate the current native pair and snapshot its
  exact current manifest/plists as the NEW transaction's fallback. Retain the
  original legacy baseline separately and unchanged. Never reuse its old journal
  authorization as if the original activation were incomplete.
- Reuse existing preflight, readiness, receipt and one-attempt recovery. The small
  required extension is an exact target-bytes input to transaction publication:
  validate definitions from those bytes, then atomically publish the original
  bytes without merging overrides or serializing JSON/plists anew.
- A failed/interrupted inverse must recover the new transaction's exact native
  fallback, not overwrite or lose it in an effort to restore legacy. Failures
  during the one allowed recovery remain terminal; automatic recovery cannot
  guarantee success when the host/filesystem also fails.
- After verified legacy return, prove exact bytes/modes/owners and loaded legacy
  dependency absence before separately approved wrapper-only restore. Leave the
  app and versioned controls unchanged and retained (also account for the running
  return controller itself); deletion is not part of this operation.

`scripts/production_control/test_return_baseline.py` exercises noncanonical JSON
and binary plists for both target and new native fallback, before/after durable
preparation, every selection/plist publication and both reload interruptions,
failed inverse and failed fallback, corrupt/revoked/foreign baseline rejection,
lock contention, owner/approval checks, unsafe paths/modes, changed inputs across
preflight and journal preparation, one-attempt recovery, and unchanged artifacts.
Inputs are revalidated immediately before preparation and publication under the
existing shared lock. Cooperating writers must use that lock; this does not
contain a malicious same-UID writer racing filesystem syscalls. Atomicity is
per-file with durable transaction recovery, not a three-file atomic swap.

No new transaction schema or recovery phases are introduced. The optional operation
and approved-baseline digest are informational provenance in a new transaction;
its fallback remains the authority for ordinary one-attempt recovery. A refusal
after durable preparation can leave a prepared transaction without a selection
write. Resolve it via separately approved ordinary recovery, never a phase edit.

**Deployment consequence:** stage a new immutable matched control version. The
existing first-install-only installer cannot upgrade the already installed v1;
that reconciliation/deployment is outside this patch and needs separate review.
Do not patch installed files in place, invent an install receipt, or restore
wrappers while native dependencies (including the return controller) remain.
All readiness, permission, same-session-resume, approval and retention gates stay
in force. No installation or production-service rehearsal was performed. See the
verification deviation below concerning a disposable neighboring test.

## Offline execution

Use each requested ABI with per-command isolated HOME, HERMES_HOME,
HERMES_WEBUI_STATE_DIR and TMPDIR under private scratch, no inherited credentials,
`-B -m unittest discover -s experiments/verity_identity -p test_production_cutover_recipe.py -v`.
Run neighboring controller unittest fixtures separately; use Ruff `--no-cache`
on the new Python file. Do not run live harnesses or application preflight.
The test imports the real Controller, substitutes fixture Host/signature/preflight,
and writes only temporary filesystem state. Subprocess calls are forbidden in
its five cases. The documentation's pure job function is executed and plist-round-
tripped, and the approved runner's argument routing/owner rejection is tested.
Passing tests mean the blocker is reproducible, NOT that production is ready.

Original recipe audit results (before the return extension): all five recipe
cases passed on Python 3.11 and 3.14.
The neighboring native-migration (2), transaction-recovery (12), native-identity
(16), and restart-control (30) cases also passed on each ABI: 65 cases per ABI
including this file. Ruff `check --no-cache` passed using the installed Ruff
executable; the first attempt via the 3.11 interpreter reported no Ruff module.
Git diff whitespace checking passed. No native/service/network calls, signing,
production reads/writes, commit or push were performed. The injected fixtures
are not evidence of installed controller byte matching or real launchd ownership.

### Return-extension verification

TDD first reproduced the missing explicit return contract, then separately
reproduced wrapper-provenance, post-preparation race, stage-hash and installed-mode
acceptance gaps before implementing their checks. Final isolated runs on Python
3.11.16 and 3.14.7 passed **72 cases per ABI**: return-baseline (9, with fault and
adversarial subcases), native migration (2), transaction recovery (12), selected
native identity (14), restart control (30), and the old inverse recipe (5).
Each file ran in its own subprocess with allowlisted environment and disposable
HOME/HERMES_HOME/WebUI state/TMPDIR. Final verification excluded
`test_swift_environment_validation_matches_python` and
`test_kernel_identity_and_dynamic_signature_on_disposable_process`; a subprocess
guard additionally rejected xcrun/swift/swiftc/codesign/launchctl commands.

**Scope deviation:** the initial neighboring native-identity discovery was not
filtered. It compiled a disposable pure Swift settings decoder and inspected a
disposable process/signature on each ABI. This violated the task's no-compile
constraint; it did not install/sign a production artifact or touch service jobs.
Those cases were excluded from final verification rather than represented as
permitted offline evidence. No network, production imports, production state
reads/writes, launchctl, commit or push was performed by this implementation.

Ruff `check --no-cache` passes for the approved runner and new test file. The
controller has three existing unspecified-encoding findings, reproduced against
HEAD with Ruff via stdin; this extension introduces no additional Ruff findings.
Git diff whitespace checking passes. These are source/fixture results only, not
installed-version matching, real launchd ownership, permissions, native dependency
absence, or same-WebUI-session continuation evidence.

The parent independently froze the delivered six-file change over
`b1c025740fe1a294aa0d6f388a9fbb2792a53638` and reran all **72 permitted tests
per ABI**. A first stricter run blocked two neighboring fixture-only Python
subprocesses (environment echo and constant fixture-module import). After
inspecting their exact code and disposable environments, a narrow allowlist
permitted only those probes; both complete runs passed. Native compilation,
CDLL calls, other subprocesses and network connections remained blocked. The
two native cases named above stayed excluded. All delivered source hashes
remained unchanged. Ruff reported only the same three encoding findings,
independently reproduced on the baseline. Focused source review is pending;
these results do not certify a new installed controller or successful cutover.

### Revocation-entry review correction (offline only)

The review found that `Path.exists()` classified a dangling
`revoked-releases.json` symlink as absent, permitting a retained-baseline return.
A new regression first failed on both Python 3.11 and 3.14 with
`ControlError not raised`, before the controller was changed.

The controller now shares one revocation-file read between ordinary
restart/recovery checks and retained-return input validation. Only
`FileNotFoundError` from the directory-entry lookup means absence. Links
(including dangling links), nonregular entries, unsafe owner/mode/ancestor
metadata, lookup/read permission errors and observed read-time replacement
fail closed. The retained-file bytes and identity (or confirmed absence) are
rechecked at every existing return prepublication boundary, including after
preflight, informational journal preparation and durable transaction preparation.
This retains the existing cooperating-writer lock contract, not containment
against arbitrary same-UID filesystem races.

Two invariant tests cover initial refusal and changed policy at those boundaries,
including real unreadable-file permission failures, injected lookup denial, and
replacement by a symlink during reading. Rejected initial inputs leave selection,
plist bytes, transaction and destructive host-call history unchanged. A policy
change after durable preparation leaves only the prepared native fallback;
selection and host calls remain unchanged. Valid absent/plain policies still
permit exact return and ordinary native restart; retained artifacts stay intact.

Frozen source over `29e5d28926666087c89e0f99fe9221e5e0a8a519` passed **74 permitted
cases per ABI** on Python 3.11 and 3.14: return-baseline 11, native migration 2,
transaction recovery 12, native identity 14, restart control 30, recipe 5. Each
module used a separate disposable HOME/HERMES_HOME/WebUI state/TMPDIR and the
inspected fixture-only subprocess allowlist. The two native cases named above
remained excluded; native API, other subprocess and network tripwires were
installed before test imports. Ruff reported only the three acknowledged baseline
encoding findings; the new tests and whitespace checks passed. Production
artifacts and services were not accessed or changed; no compilation, signing,
native process inspection, installation, commit or push was performed. This
corrects the source blocker only; installation and all live acceptance gates
remain unverified.

The parent independently matched the delivered source hashes and froze them over
the same unchanged controller dependencies. All **74 permitted tests per ABI**
passed again. A separate replay placed the new regression over the original
`29e5d28926` controller and reproduced `ControlError not raised` for the dangling
entry on both ABIs. No real-native cases were enabled. Focused re-review
`deleg_5ac429c9` remains pending; no new installed controls, signature verification
or live service action is implied by this checkpoint.

