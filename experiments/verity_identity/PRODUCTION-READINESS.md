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
request rollback. There is no rollback-only CLI switch. The installer restore is
wrapper-only and rejects changed selection; it cannot undo an activated pair.
A post-success return-to-legacy procedure remains to be designed and verified;
do not change a verified transaction's phase to manufacture recovery authority.
The old `prepare_cutover.py` rebuilds Python overrides and is not a native recipe.

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

The proposed direction, not yet implemented or verified, is one durable cutover
job plus a narrowly scoped record consumed inside WebUI. Bind operation, initiating
session, profile, workspace and expected release; persist admission identity before
worker execution and reconcile it against a nonsecret execution receipt. Duplicate
triggers must resolve to the same disposition, busy work must remain pending, and
uncertain dispatch must stop for reconciliation rather than repost. Resolve only
authorized compression descendants before mutation and revalidate at admission.
Do not weaken authentication or copy browser credentials to make this work.

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
2. Final-identity AppleEvents authorization-only coverage is still omitted. Preserve
   the original no-content test boundary; lab Finder automation is separate evidence.
3. Reconcile the original continuity matrix against final-identity evidence. Current
   final-path checks use separately signed temporary settings, one permission and ABI
   per root, and the `agent` role. They do not prove same-temporary-host ABI switching,
   a changed native-code rebuild under the production signer, or both real production
   descendant paths. Keep earlier lab rebuild/both-role evidence distinctly labelled.
4. Revalidate the exact matched installed host/control, staged native manifest and
   both definitions, retained rollback material, and independent activation/recovery
   procedure. Selection and activation remain unarmed until the conditional resume
   requirement and readiness gates pass. The existing controller lacks a byte-exact
   post-success return to legacy; `PRODUCTION-CUTOVER.md` records the reproduced
   limitation. Synthetic failed-activation rollback does not close that gap or prove
   live wrapper restore.
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
