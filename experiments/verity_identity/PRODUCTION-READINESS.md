# Production readiness: installed, not cutover-ready

The reviewed isolated gates are complete; see `COMBINED-CANARY.md`. They do
not constitute a production cutover-ready artifact. The operator requested
completion through readiness, with notification only at readiness or a genuine
blocker. The operator subsequently authorized autonomous production selection,
reload and service restart **conditional on a verified method to resume the same
initiating WebUI session after restart**. That condition is not yet satisfied;
no cutover job is armed. This does not waive the permission, continuity or recovery
gates below. Logout/login and reboot remain separately unapproved.

## Production signer and recovery gate

The operator approved a dedicated production signing identity, code-signing-only
trust, and encrypted 1Password recovery. 1Password for Mac 8.12.36 is installed at
the explicitly requested `/Applications/1Password.app`; CLI 2.39.0 is installed at
`/opt/homebrew/bin/op`. Both signatures verified. Desktop sign-in and CLI integration
are now verified. Headless and PTY authorization timed out; the user approved a
native request from a dedicated Terminal.app tab, after which vault access passed.
This successful alternative does not isolate the cause of the headless timeout.

`create_production_identity.py` generated a new RSA production identity in memory,
saved encrypted PKCS8 and its strong passphrase in concealed fields of the explicitly
selected Private vault (not Shared), then fetched the exact item by vault/item ID.
Every recovery field matched, decryption succeeded, and a signing challenge verified
against its certificate. Only the recovered key was written to an owner-only
transient file and imported non-extractable with the codesign ACL; that file is gone.
The operator approved macOS's trust request. Read-back shows exactly one trust policy,
CodeSigning, in the user domain. An actual copied Mach-O was signed using this restored
key, verified against its leaf pin, and executed successfully.

Public production certificate SHA-1: `B72A53676319B035EF637A6DEF27F026009D989C`.
Nonsecret local checkpoint: `~/.hermes/signing/verity-production-v1/identity.json`.
Recovery item identifiers stay in that local checkpoint, not in tracked source.
No secrets were printed or passed in command arguments. The initial source review
found two blockers: partial-key writes were outside the cleanup boundary, and trust
validation checked the name without the policy identifier. Two regression methods
reproduced five failing subcases on the original code (partial write/close and three
invalid identifiers). Serialization/write now sit inside `try/finally`, and trust
validation requires exact `CSSMOID_APPLE_TP_CODE_SIGNING` bytes (`2a864886f763640110`).
The constant was independently compared with Security.framework's exported symbol;
a fresh user-domain trust export passes the stricter validator. The real transient
key file remains absent. No repro used actual private material or Keychain writes.

Eight signer tests (including ordinary serialization/write/close/checkpoint/import
failure paths) and all 37 affected/neighboring experiment tests pass on Python 3.11;
changed-file Ruff checks pass. This does not claim cleanup survives process kill,
OS crash, or filesystem unlink failure. Independent focused re-review found no
blocking findings in scope, confirming both fixes and their regression coverage.
The signer/recovery gate is complete. Host/control installation is now complete;
final-identity permission validation remains partial. See the current checkpoints
below rather than treating this historical signer gate as cutover readiness.

## Historical signing prerequisite (resolved above)

Read-only discovery returned exactly one valid code-signing identity:
`Verity Lab Code Signing`, SHA-1
`A17BCFC88CD3BB95555C22CB8B8FA36D4F6336CE`.
No usable Apple-issued identity was listed in the current keychain search context;
this is not evidence that the operator lacks an Apple developer account.

The existing certificate is self-issued and valid from September 27, 2026 through
September 24, 2036. The provisioning source imported its key with `security import
-x` (non-extractable), deleted the transient key file, and recorded a lab-only
purpose. No export was attempted, no private key was read, and no independent
recovery copy has been established. The prior approval expressly limited this
identity and code-signing trust to an isolated experiment, not production.

Do not silently promote that identity or try extracting its non-extractable key.
Resolve the explicit production signing decision first:

- An operator-approved Apple-issued identity with a verified recovery procedure; or
- A dedicated local production identity, code-signing-only trust, and an explicitly
  authorized encrypted off-device recovery destination. Create and validate recovery
  before destroying temporary provisioning material. Keep all private material and
  recovery secrets out of source, logs, argv, reports and chat.

The final bundle `com.charles.verity` at `~/Applications/Verity.app` needs its own
system consent. Existing lab grants are not production grants. Do not rename or
transplant TCC records. Provisioning/trust and consent require operator involvement;
no test can eliminate those approvals.

## Native environment and migration integration

The optional signed bootstrap environment and narrow legacy-to-native definition
migration are implemented. The stager now supplies explicit HOME/TMPDIR and the
common selected HERMES_HOME without altering selected source/runtime dictionaries.
Offline migration tests prove exact manifest and binary-plist rollback on failed
native readiness. A lab-only live environment gate passed 70 cases across both
roles, with independently verified process/group/job cleanup; see
`PRODUCTION-STAGING.md` for evidence and two retained harness failures/fixes.
These are not final production identity, installation, messaging or cutover tests.
Environment/staging integration review reported only the already-fixed cleanup
finding and no other blockers. The new synthetic migration harness passed six live
cases with independent cleanup verification and unchanged production baseline;
see `../../NATIVE-MIGRATION-CANARY.md`. Focused current-source review
(`deleg_4d2e07e8`) found no blockers in the synthetic containment, rollback,
process/group evidence or cleanup/publication scope. Final production artifact
installation and permissions are not covered by that clearance.

## Current install-only checkpoint

The operator's “go” approved the reviewed install-only and bounded temporary
same-identity permission-test proposal, not selection/restart. The real app,
versioned controls and four wrappers are installed and separately verified at
final paths. Both candidate definitions and source/runtime inventories validate;
legacy selector/plists/process identities remain unchanged, with health `ok`.
Passive registration resolves the final app path. See `PRODUCTION-INSTALL.md`
for the exact execution/read-back scope. This closes installation, not live
wrapper restore or cutover readiness. Earlier unanswered prompts were superseded
by the operator’s explicit install/test approval; permission evidence follows.

## Current permission checkpoint

See `PRODUCTION-PERMISSIONS.md` for exact reviewed source, receipts and limits.
The initial 15 check-only runs observed the new identity without grants. Following
operator consent, 28 fresh check-only runs covered the 14 original named workers
on copied Python 3.11 and 3.14. Thirteen named workers per runtime reported allowed,
including actual read-only Messages/Safari descriptor opens and fixed Finder
AXRole. All completed runs verified the isolated live chain, clean exits, exact
job/PID/PGID removal and original app restoration. Independent installed-artifact,
wrapper, legacy selector/plist/process and health read-back passed.

Location's consent request timed out, and fresh checks remain `not_determined`.
One approved Local Network connection succeeded without application data, with
`allowed=null`: connectivity only, not permission attribution or enforcement.
The subsequent conditional deny/allow test was approved only if a distinct Verity
entry could be found. No such entry was exposed by the inspected Local Network
pane, so no toggle was changed and no additional connection was attempted. This
UI observation does not establish absence from the underlying OS permission store.

Read-only Apple documentation research establishes that consent-only Location
requests are available on macOS and documents a foreground requirement for showing
a prompt. The macOS usage key is already correct. Neither the documentation nor
the timeout proves that foreground eligibility or Python responsibility caused
this failure. The retained delegate/run-loop implementation does not support an
obvious missing-run-loop diagnosis; it discards initial not-determined callbacks,
so callback delivery cannot yet be distinguished from a missing consent transition.
The operator explicitly approved one instrumented consent-only diagnostic:
own bundle/activation/run-loop/callback observations, no location sample, no
foreground activation and no production restart. Implementation is committed at
`9da4bf49469017a53995313c44ca622309030109`; the parent reran 92 offline tests on
each supported ABI. Focused source review `deleg_ea691778` found no concrete
blocker. The one approved live diagnostic finished `incomplete`/`ConsentTimeout`:
initial/final status 0, one callback with status 0, 1909 main-thread run-loop pumps.
The Python worker's main bundle did not match Verity's ID/path or expose its macOS
usage string; it was inactive, with unknown activation policy. This does not prove
Core Location's responsible client or the cause. Original app restoration, exact
experiment cleanup and independent installed-artifact/legacy-service/health read-back
all passed. The single live diagnostic approval is exhausted; see its retained
result in `PRODUCTION-PERMISSIONS.md`.
Apple references independently retrieved by the parent:
[requestWhenInUseAuthorization](https://developer.apple.com/documentation/corelocation/cllocationmanager/requestwheninuseauthorization()),
[authorization overview](https://developer.apple.com/documentation/corelocation/requesting-authorization-to-use-location-services),
and [NSLocationUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocationusagedescription).
The method page includes cross-platform wording; it does not establish a causal
result for this specific launchd-native-host/Python-child topology.

## Final-identity matrix and activation audit

Read-only audit `deleg_1c5d0ea9` found the matrix below still open. The parent
inspected the relevant worker, host compiler and controller paths; this is source
analysis, not additional live permission or activation evidence.

- The existing permission harness pins one ABI and the `agent` role. Its final-path
  observations do not establish ABI switching under unchanged signed settings.
- `SIGNED-REBUILD.md` proves changed-code/rebuild/rollback for the lab identity;
  `COMBINED-CANARY.md` proves both synthetic roles and real WebUI terminal descendants
  under that lab identity. Neither transfers those passes to `com.charles.verity`.
- A bounded final-identity extension would seal both copied runtimes, fixed roles
  and a finite check-only sequence before execution; use unchanged signed settings
  across ABI cases. Build A/B/A must establish actual executable-code differences,
  not merely different signatures or UUIDs, and preserve the original installed
  bundle separately. Do not weaken the existing copy-only `code_payload()` equality.
- Fixed Finder authorization can reuse only `probe.py`'s descriptor creation,
  `AEDeterminePermissionToAutomateTarget` and disposal. Calling its whole
  `automation()` would also execute an AppleEvent and count windows, outside the
  authorization-only boundary. Existing frozen probes remain unchanged.
- Those additional final-path executions require explicit bounded approval and
  focused review. No more Location or network attempts are authorized by this audit.

The activation entry point is `approved_restart_job.py` with
`--restart --yes --activate CANDIDATE --reload`, directly owned by launchd. This
interface description is **not an activation command approval or a ready recipe**.
The matched paths, unarmed independent job, validation and recovery procedure must
be supplied and exercised before cutover. CLI check/preflight imports application
modules; static inventory validation is not an equivalent test.

`Controller.recover_locked()` restores an incomplete transaction's original
manifest/plist bytes once. It returns without restoring a terminal `verified`
transaction. Repeating restart after successful activation therefore does not
request rollback. The installed controller has no explicit post-success return
operation. The source extension delivered by `deleg_940d4efe` task 1 now adds
`--return-baseline INSTALL_RECEIPT_SHA256`, preserving exact legacy target bytes
and recording the current native bytes as a new one-attempt fallback. The parent
independently passed 72 permitted fixture tests per Python ABI with native/network
tripwires; see `PRODUCTION-CUTOVER.md` for the author's disclosed earlier
no-compile scope breach and the parent's bounded verification. Focused review
`deleg_34b0714c` task 0 found one blocker: a dangling `revoked-releases.json`
symlink reports false from `Path.exists()` and is treated as absent by both the
new retained-input preparation and existing revocation check. Remediation
`deleg_4a327158` is delivered. The parent independently replayed the new regression
against the old controller on both ABIs and observed the dangling-policy subcase
fail with `ControlError not raised`. The fixed controller independently passed
**74 permitted tests per ABI**, with the same two real-native cases excluded and
pre-import native/network/subprocess guards. Delivered source hashes match the
parent's frozen snapshot and remained unchanged during verification. Ruff still
reports only the three previously reproduced baseline encoding findings.

The shared reader now uses directory-entry inspection: genuine absence is distinct
from dangling/ordinary symlinks, nonregular or unsafe files, permission failures
and observed read-time replacement. Existing return prepublication boundaries
revalidate the retained policy bytes and identity. Regression fixtures verify
refusal before selection or destructive calls, preserving the original transaction
before preparation and the exact native fallback after durable preparation.
Focused re-review `deleg_5ac429c9` is pending. These are source/fixture results, not
an installed-controller or live rollback claim.
A new immutable control version with matching stage and install provenance is
still required; the first-install-only installer is not an upgrade path.
The installed artifacts have not changed. Installer restore is
wrapper-only and cannot undo an activated pair. Never change a verified
transaction's phase to manufacture recovery authority.
The old `prepare_cutover.py` rebuilds Python overrides and is not a native recipe.

### One-hop installed-control upgrade design

Source review `deleg_ff8f4896` recommends a bounded v1-to-v2 upgrade, not a general
upgrade framework. The parent independently inspected the first installer,
stager wrapper generation and signed settings. Existing `restore()` keeps the app
and controls while rewriting the original receipt phase; `install()` still refuses
the existing receipt and destinations. They cannot be composed into an upgrade
that preserves the original receipt bytes.

Every new control-version path changes the generated launcher wrapper hash, which
is embedded in signed app settings and candidate identity. Updating only installed
controller files or wrappers is therefore not a matched deployment. A fresh stage
and matching signed app are required; neither was produced by this design review.

Offline implementation `deleg_f52dd994` is isolated on the upgrade worktree at
`114a681e7babfee835a587085ad636b9787eb8df`. Its scope is the installer, focused tests
and installation documentation; it does not edit the concurrently repaired
controller. Required invariants are:

- Keep the original install receipt, stage and controls unchanged. Retain the
  original signed app by rename, never rebuilding or re-signing its replacement.
- Admit only an intact installed-v1 state with exact legacy selection/plists and
  v1 wrappers. The new stage retains those v1 wrappers, not the legacy originals.
- Before mutation, persist a separate upgrade journal binding the original receipt
  and new stage. Publish a separate immutable committed receipt only after full
  read-back. Recovery restores the v1 installed state before commitment, not the
  pre-install legacy wrappers; committed success requires verification, not a
  blind rollback.
- Derive bounded destinations and revalidate observed artifacts around each copy,
  app rename and wrapper publication. Unknown identity/dependency state refuses.
  The existing two-job dependency check alone is not a census of independent
  native hosts. Advisory locking cannot prevent arbitrary nonparticipating launches.
- Keep selector/plists, services, permissions and existing candidates unchanged.
  A later upgraded-wrapper restore uses the original legacy wrapper records only
  after verified return to the legacy pair and affirmative dependency absence.

The return controller must subsequently distinguish **original baseline
provenance** from **current deployment provenance**, explicitly pinning both root
and committed-upgrade receipts. No copied historical fields, recursive chain
lookup or implicit latest receipt may substitute. That integration is deferred
until the policy fix and installer receipt contract are delivered; current return
unit fixtures do not prove install-chain integration. Fresh staging/signing,
install-only replacement and live verification remain separately gated. No live
upgrade, recovery, restore or cutover was executed for this checkpoint.

## Final-identity continuity implementation checkpoint

The bounded continuity implementation from `deleg_2334554e` is delivered in
`verify_production_continuity.py`; see `PRODUCTION-CONTINUITY.md`. It seals one
check-only permission and the finite A/B/A, both-synthetic-role, both-ABI matrix.
This is implemented test infrastructure, not completed final-identity evidence.
The parent independently reran 118 offline tests per ABI (113 continuity and
neighboring tests plus five old-controller cutover-recipe fixtures) on a frozen
snapshot over `5ba4734d89b4bb7291474d837761ef1d9a102a2c`. A fresh 113-test run on
both ABIs also passed after extending fault coverage to explicitly distinguish
A signing, B compilation and B signing failures. Ruff passed; frozen host/probe
sources remain unchanged. Concurrent rollback-controller edits were excluded.

Focused cleanup/recovery and execution-contract reviews (`deleg_818692a8`) are
complete and found **four issues in the original implementation**, not clearance. The parent compared
the reviewed harness to `4233d2fdc5` and independently inspected all cited paths:

1. The frozen host emits `host-refused` and `spawn-error` before its ordinary
   process event. The continuity parser rejects both; cleanup/recovery parses
   these retained outputs before its independent census and cannot restore even
   after all experiment processes are absent. Accepting their bounded failure
   schemas must not allow a failed host to satisfy execution/continuity checks.
2. A first SIGINT/SIGTERM during final cleanup/restoration can interrupt that
   reconciliation and leave the original retained away from its final path.
   The current first-interrupt promise is therefore not established. Test the
   finalization and recovery phases, not just interruption during a worker run.
3. Admitted dependency inventories can make the serialized plan exceed its own
   4 MiB reader limit after preparation/signing. Bound compatible serialized
   records before signing/publication, including the larger swap-receipt envelope
   before moving the installed app.
4. Rehashing all runtime/bridge inputs after worker readiness runs within the
   frozen worker's 30-second GO deadline without a time bound. Slow admitted
   inputs can expire the worker before any check. Expensive validation must not
   consume that handshake; retain point-of-use and fresh identity checks rather
   than treating a stale ready event as a live worker.

The last two were source-established conditional failures, not measurements that
the actual installed runtime exceeds those limits. Remediation `deleg_9392746c`
delivered changes confined to the three continuity files. The parent independently
replayed the four historical red groups against `4233d2fdc5` on Python 3.11 and
3.14, observing the expected restoration, interruption, receipt-admission and GO
failures. The delivered code then passed **124 tests per ABI** over committed
controller `0d06d7720956b39ef2d8f086a7e37a0b5e31f4f7`. Pre-import native/network/
subprocess guards permit only inspected disposable fixture commands. The first
parent run found two guard mistakes, not product failures; fixing only the guard
produced green results. Code hashes matched the delivery and remained unchanged;
changed-file Ruff passed. Focused re-review `deleg_41bf0942` is pending.

The fixes accept only validated failure-only host records, latch the first signal
through reconciliation, bound actual encoded receipt envelopes, and move full
inventory validation before bootstrap. A 20-second admission interval and fixed
bounded point-of-use checks replace the after-ready full traversal. Its temporal
sealing limits are explicit in `PRODUCTION-CONTINUITY.md`; it is not an atomic
freshness or hostile same-UID guarantee.

**A new parent-reproduced reporting defect keeps the interrupt gate open.** A first
signal while restoring caller handlers, after `ReconciliationSignals.__exit__`
has skipped its interruption-receipt decision, leaves the returned status failed
but the durable result completed with no companion interrupt record. A disposable
full-run counterexample reproduced this on both ABIs. Cleanup, original restoration
and caller-handler restoration all passed; durable invalidation did not. The new
late-interrupt companion-report contract must cover that exit boundary before any
live use. Earlier green totals are retained, not treated as clearance over this
newly exposed case. No live continuity preparation or execution is cleared; frozen
host/base probes and production artifacts remain unchanged.

No real compilation, signing, continuity run or new permission request was
performed for this checkpoint. The Finder implementation and its parent 98-test
evidence were already committed at `b0065100b9`; receiving the same implementation
report again does not establish a new live Finder result.

## Same-session autonomous resume audit

Source-only audit `deleg_22cc267f` inspected the selected frozen WebUI and Agent
release. It found no demonstrated durable, idempotent, credential-free external
resume interface. This is an implementation gap, not proof that autonomous resume
is impossible. No API call, authentication change or restart was performed by the
audit. The parent independently inspected `start_session_turn()` in that release:
it is an in-process entry point, and it resolves workspace/model state without the
HTTP entry point's compression-lineage guard.

- `POST /api/chat/start` can target a session but requires authentication; absence
  of browser Origin/Referer affects CSRF handling, not authentication. The audit
  found no caller-supplied durable idempotency key. A lost response must not cause
  a blind retry; a client-side sent marker does not close the dispatch/crash gap.
- `api.routes.start_session_turn()` must run inside the owning WebUI process.
  Importing it from an independent job creates separate runtime state, not an
  enqueue into the running WebUI. Busy admission is not durable deduplication.
- Agent cron creates separate execution sessions. Origin delivery and transcript
  mirroring do not establish continuation of the initiating WebUI session. The
  audit found deferred process-wakeup state to be in-memory; ordinary checkpoint
  recovery alone does not prove safe dispatch across a restart.

Independent source audit `deleg_940d4efe` task 2 confirms those limits. An
independent one-shot can durably commit to at most one POST, but a crash between
that commitment and sending loses delivery; after an ambiguous response it cannot
retry safely. The frozen HTTP path also lacks an atomic expected session-revision,
workspace and lineage comparison at admission. A logged-in browser fetch avoids
credential extraction, but does not repair those contracts and adds a browser
dependency. No such POST or browser authentication action has been attempted.

The initial implementation assignment (`deleg_34b0714c` task 1) returned only
source findings: **no implementation and no executed tests**. The parent confirmed
the worktree remains unchanged at the selected WebUI source commit. Inspection
shows workspace/model mutations before shared admission, stale-state cleanup
before the session lock, and a best-effort journal append after pending-state
publication. PID-sharded append locks are not an atomic operation claim. A local
claim alone cannot fence Gateway/runner admission or canonical-session rotation.

A narrower follow-up (`deleg_e839d257`) is limited to explicitly supported local
WebUI execution; Gateway, runner, non-WebUI and unknown ownership must refuse.
It must implement a real shared local admission boundary before mutation, private
durable operation deduplication and an actual worker-entry receipt, with isolated
owning-process integration tests. Normal delivery plus safe refusal after an
ambiguous durable claim is the target, not guaranteed eventual execution across
arbitrary crashes. Unsupported external writers remain outside that bounded
claim; they must not be silently routed locally. No source-only audit, unconsumed
request or standalone mocked state machine satisfies the cutover condition.

A parent read-only metadata check found the initiating session open, sourced from
WebUI, in the requested profile/workspace, with an active stream and pending turn.
That is not idle/admission evidence and does not establish the effective backend;
missing explicit backend settings are not proof of local ownership. No live
request was written, no API called, and no turn injected.

The proposed direction, not yet implemented or verified, is one durable cutover
job plus a narrowly scoped record consumed inside WebUI. Bind operation, initiating
session, profile, workspace and expected release; persist admission identity before
worker execution and reconcile it against a nonsecret execution receipt. Duplicate
triggers must resolve to the same disposition, busy work must remain pending, and
uncertain dispatch must stop for reconciliation rather than repost. This first
local-only path must reject a rotated/sealed session rather than following an
unverified descendant or reopening a parent. Do not weaken authentication or copy
browser credentials to make this work.

The consumer must be present in the release that boots after cutover; an unconsumed
record is not a recovery mechanism. Before arming, use isolated state to verify
browser-independent restart/resume, duplicate and lost-response behavior, crash
boundaries, busy/human-send races, repeated compression, and rejection of wrong
profile/workspace/release or explicitly closed sessions without mutation. Evidence
must establish turn execution, not merely queue acceptance. These checks and the
bootstrap/staging path remain open; this audit does not satisfy conditional cutover
authority.

## Remaining gates and boundaries

1. The approved Location diagnostic is complete as an observation, not a grant.
   Resolve the remaining Location and Local Network limitations or obtain explicit
   acceptance; neither is silently
   removed from the requirements. A missing Settings target stops the scoped
   deny/allow experiment, not permission to change unrelated Python/app grants.
2. Final-identity AppleEvents authorization-only live coverage remains open.
   The fixed Finder implementation, parent offline tests and focused static review
   are complete; no live execution is implied. Preserve the no-content boundary;
   lab Finder automation is separate evidence.
3. Reconcile the original continuity matrix against final-identity evidence. Current
   final-path checks use separately signed temporary settings, one permission and ABI
   per root, and the `agent` role. They do not prove same-temporary-host ABI switching,
   a changed native-code rebuild under the production signer, or both real production
   descendant paths. Keep earlier lab rebuild/both-role evidence distinctly labelled.
4. Revalidate the exact matched installed host/control, staged native manifest and
   both definitions, retained rollback material, and independent activation/recovery
   procedure. Selection and activation remain unarmed until the conditional resume
   requirement and readiness gates pass. The installed controller lacks a byte-exact
   post-success return to legacy. Its source extension has parent offline evidence
   but its focused review found a revocation-policy failure and its immutable
   deployment path remains unverified; `PRODUCTION-CUTOVER.md` records the distinction. Synthetic failed-activation
   rollback does not prove live successful-cutover return or wrapper restore.
5. The operator has authorized autonomous selection/reload/restart once a reliable
   same-session resume method is verified. Verify that method independently before
   interruption; a cron's fresh session or a recovered transcript alone is not the
   requested continuation. Resolve pre-cutover gates and explicit exception decisions
   before consuming this authority. Verify both real service chains, protected checks
   and separately approved messaging afterward. Logout/login and reboot still need
   separately agreed disruption timing; process restarts are not reboot evidence.

Do not use the inherited `install_controls.py` or `prepare_cutover.py` as shortcuts:
those older paths target schema-1/Python launch assumptions rather than this reviewed
native migration. Use the current reviewed stage/install/controller mechanisms.

The app, versioned controls and maintenance wrappers changed under install approval;
OS grants changed under consent approval. The original app is restored after each
bounded experiment. The running production services, legacy selection and launchd
definitions have not been switched or restarted. A cutover-ready receipt has not
been published, and actual production descendant verification remains conditional
on satisfying the newly authorized conditional activation gates.
