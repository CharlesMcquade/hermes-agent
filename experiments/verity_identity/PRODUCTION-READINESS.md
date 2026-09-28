# Production readiness: offline maintenance preparation; live deployment blocked

## Current authorization and integrated baseline

The operator approved expanding **offline implementation and testing** to a
controlled maintenance approach. This is not approval for live downtime, installed
artifact changes, signing, elevated observation, logout or reboot. Final live go is
still required. The earlier admission review remains a design constraint, not an
instruction to bypass unreadable identities or silence supervision.

The reviewed one-hop installer/upgrade history is now merged with the exact gateway
wrapper identity repair and separately pinned v1 return controller. On a frozen
integrated snapshot, the parent independently replayed 48 installer/staging tests
and 71 native/controller/migration/return tests on each of Python 3.11.16 and 3.14.7.
Two installer subprocess cases and four controller native/compiler/subprocess cases
were explicitly excluded. Permitted synthetic launcher-check subprocesses used
strict fixture argv/environment/inventory checks; no production imports, native
API calls, real compilation/signing or service changes were executed.

The initial installer replay's cleanup was rejected because relative dirfd paths
were evaluated from a working directory outside fixture scratch. The unchanged
source and guard passed after running from the isolated fixture directory. This
was a harness setup failure, not a product regression or a weakened safety check.

Offline implementation now provides upgrade-aware exact return and retained-host
staging without recompilation. Parent replay of their combined frozen snapshot
passed **131 tests on each of Python 3.11.16 and 3.14.7**, with seven explicit
subprocess/native/compiler exclusions, isolated state and no guard violations.
The real fixture chain runs first install -> fresh stage -> upgrade -> native
activation -> exact return -> original-wrapper restore. No synthetic completion
receipt substitutes for that return. OS/signature/health/dependency observations
are adapters, not live evidence. Focused reviews `deleg_66b6b131` are pending.

Parent negative replay on each ABI also reproduced the old controller's
`Wrong installed control identity` refusal, and behavioral staging mutants caused
one forced-compilation assertion and four missing-stability assertions. Initial
scratch mutant writes were refused by the file tool; the accidentally unchanged
copies passed and were not counted as negative evidence. After properly applying
the mutations, both ABIs failed as intended with zero errors. Three existing Ruff
encoding findings matched the baseline exactly; no new diagnostics were present.

Maintenance publication remains **unimplemented**, not fixture-green. The worker
stopped rather than ship a permissive callback. The parent replayed two concrete
counterexamples on both ABIs: a pre-imported controller remains callable after
flock release, and the unlocked legacy launcher reaches an intercepted exec while
that lock is held across all three app arrangements. These do not prove any such
consumer is running in production, or that the native host was executed. See
`MAINTENANCE-CONTRACT.md` for the missing consumer-retirement/launch-exclusion
mechanism. Merely approving downtime cannot add a protocol to immutable v1.
All completed preparation remains offline; there is still no cutover-ready claim.

## Latest live outcome supersedes the preparation checkpoint below

The supervised production activation was attempted and the installed controller
reported `Readiness timeout: Native child is not direct host child`. It completed
its one-attempt recovery with `rolled_back`, not native success. Independent
readback verified the original selector and both plist bytes/modes/owners, unchanged
installed app/control/wrapper provenance, healthy legacy service identities,
shallow/deep health and all five served assets. No production permission operations
were completed in the native window. Successful-native exact return remains untested.

The selected Agent command runs `hermes_cli.stderr_timestamp`, which uses `Popen`
to start the inner `hermes_cli.main gateway run --external-supervisor` command.
The installed native `pair()` instead requires the gateway-state PID to be the
native host's direct child and to match the outer selected argv. That cannot
validate this supported wrapper topology. The recovered legacy process chain
matches both selected outer and inner argv and the direct wrapper-to-gateway edge.
The native window's full process identity chain was not retained, and the original
error does not name the service; do not overstate those observations.

The narrow offline repair now validates the exact selected wrapper and gateway
separately, preserving PID/UID/executable/argv/birth/signature checks and including
the wrapper in stability rechecks. Independent frozen replay passed 71 tests on
Python 3.11.16 and 3.14.7; both added invariants failed with the old validator's
`degraded != healthy` result on each ABI. Four subprocess/native/compiler tests
were deliberately excluded, with no offline guard violations. Ruff and whitespace
checks passed. Focused source review `deleg_a58f3994` is bounded-clear: the parent
matched the reviewed runtime, tests, controller and watchdog to current bytes.
Generic ancestor/descendant acceptance is not used. Installed artifacts remain
immutable; do not retry with the old activation controller, watchdog or return
executor. These fixture results do not establish production acceptance.

### Current immutable-deployment blocker

The deployment review traced all four maintenance wrappers to their immutable
control version, and the launcher wrapper digest into signed host settings. A
corrected activation-only executor would leave watchdog and routine restart on
the old validator. There is no supported controls-only update. The existing
one-hop upgrade can publish a new matched app/control version and retain the old
artifacts, but it is not presently a complete deployment-and-return route:

- Its default admission requires readable, stable identities for every PID above
  1. A parent read-only necessary-condition probe used the unchanged identity API:
  self inspection passed; one protected UID-0 process failed
  `Cannot read process birth/ownership` with errno 1 (`EPERM`). PID/UID/start metadata
  from `ps` was stable around that attempt, but is not a substitute for the required
  kernel identity. The initial kernel-only discovery could not identify a system
  target; the bounded follow-up used metadata-only `ps`, never command or environment
  output. This is an observed live admission prerequisite failure, not an executed
  installer attempt or proof that a privileged attempt would succeed.
- The source controller now implements the explicit root+upgrade-pinned exact
  return and emits the linkage the installer requires. Real composed fixtures
  pass independently; focused source review remains pending and no installed
  controller or native-success return has been exercised live.
- The source stager now implements explicit retained-stage/report-pinned executable
  reuse before signing, preserving unchanged host source and canonical Info.plist.
  Fresh signing can alter signature bytes, so it still does not promise identical
  whole signed executable bytes. This path is offline-tested, not live-signed.

The follow-up source review `deleg_0388c1fa` is complete. Parent inspection agrees:
there is no currently supported install-only admission relaxation. The advisory
lock serializes participating controllers/watchdog ticks, but wrappers import their
versioned modules before locking; the launcher and native host do not take that
lock. The installer performs two app renames with a gap before publishing matching
wrappers. Retaining an old inode does not preserve the old pathname or launcher
binding for an already-starting consumer. Repeated process snapshots, including a
privileged snapshot, are not a launch barrier.

The approved offline maintenance investigation must establish exclusive control
of relevant launches/maintenance entrypoints, quiesce existing relevant consumers,
and prevent new ones through publication and recovery. Unknown relevant ownership,
retained old-code holders, or uncertain launch exclusion must refuse. A verbal
maintenance declaration, arbitrary PID/UID exclusions, or an `EPERM` skip cannot
satisfy that obligation. The current v1 has no complete consumer set or retirement
handshake; the permitted installer-only work could not bridge that bootstrap gap.
The installer was left unchanged rather than claiming a safe maintenance path.

Before live use, the revised boundary needs regression evidence for an old controller
paused after import but before locking, an unlocked launcher, native startup across
each rename, unexpected selected descendants, dependency drift after journal intent,
and exact retained-artifact recovery at every partial publication. The source-only
reviews did not themselves authorize implementation or interruption. The subsequent
operator approval at the top of this document permits offline preparation only;
no maintenance interruption, elevated observation or live publication is approved.
Do not disable watchdog, overwrite v1, or rewrite its receipt to force admission.
Deployment stays blocked until the implementation, evidence and final live approval
are complete. This does not reintroduce automatic continuation or the entire future-
upgrade roadmap as trial prerequisites.

Fresh independent readback still reports healthy legacy services, exact original
selector/plists, unchanged installed artifacts and both one-shot jobs absent. No
new restart, signing, permission operation or installer mutation occurred. Private
scalar diagnostic and matched review hashes are retained at
`verity-native-topology-parent-thzs400t/review-reconciled.json` under configured
scratch; the source review and offline repair gate are closed, deployment is not.

## Historical preparation checkpoint

The reviewed isolated gates are complete; see `COMBINED-CANARY.md`. They do
not establish universal macOS permission inheritance or production acceptance.
The operator has now accepted a **supervised production trial**, including a brief
WebUI interruption and manually sending “continue” after reconnecting. This replaces
the earlier autonomous same-session-resume condition for this trial only.
No cutover job is armed. Logout/login and reboot remain separately unapproved.

## Current scope: supervised trial, not the entire upgrade roadmap

The immediate acceptance path is: verify a clean return route, activate the already
installed signed host against the unchanged frozen Agent/WebUI pair, then check
real production descendants and the scoped tool operations. Preserve the original
selector/plist bytes and installed app/wrapper provenance. No TCC resets, recordings,
location samples, new Local Network diagnostic connections or content collection
are added to the existing consent scope.

Automatic continuation, future host/ABI upgrades and full upgrade-controller
composition remain useful separate work, **not prerequisites for this supervised
trial**. Location and Local Network limitations remain disclosed rather than being
silently relabeled as passing. Historical gate descriptions below retain their
original scope; they must not reimpose the superseded autonomous-resume condition.

Installed v1 ordinary reverse activation restores Python argv but leaves native
`AssociatedBundleIdentifiers` and `AbandonProcessGroup` settings behind. Source
review and the parent's installed in-memory definition check agree. That is not
the clean permission/launchd fallback required for this trial. The narrowly scoped
separately pinned immutable return controller is now staged without replacing the
installed app, controls or wrappers. Its source checkpoint passed 56 hermetic tests
on each of Python 3.11 and 3.14, independent parent replay and bounded source review.
Fresh retained-bootstrap subprocesses verified direct CLI sibling imports, parent-
ownership refusal, installed-v1 receipt/control/wrapper provenance and the expected
refusal while legacy remains selected. Real static runtime validation also passed.
This is not yet a live successful-native return. The prepared private one-shot
activation and return definitions are unarmed, with exact digests and commands in
a local durable receipt; no production restart has been performed.

Parent live read-only checks passed the installed signature/inventory/settings,
control/wrapper provenance, exact retained baseline, loaded legacy identities,
shallow/deep health and served assets. Source/runtime inventory validation passed.
The unchanged installed `probe()` calls also passed using the retained bootstrap
interpreter inside a macOS sandbox denying network access, real-state writes and
home-data reads outside the approved runtime/control/fixture paths. This is
component evidence, not a full native startup: combined `preflight()` inside that
sandbox correctly refused the real environment file's accessibility check, so
validation and isolated imports were exercised separately rather than granting
imports access to credentials. Production selection and services remain unchanged.

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
Focused source-only re-review `deleg_5ac429c9` is **bounded clear**: the dangling
policy blocker is fixed without a new concrete blocker in the reviewed return,
ordinary restart and recovery paths. The parent independently inspected the cited
reader, retained-input and prepublication paths, and matched the reviewed controller,
runner and return tests byte-for-byte to committed `0d06d77209`, the current source
and the parent 74-test-per-ABI receipt. The revocation source-review gate is closed.
No new execution was needed for this documentation-only closeout; the existing
red/green evidence remains the test basis. Recovery still consumes its one allowed
attempt before reporting policy refusal as `rollback_failed`, never unsafe success.
These are source/fixture results, not installed-controller, upgrade, live rollback
or autoresume acceptance; no malicious same-UID containment is claimed.
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

Offline implementation `deleg_f52dd994` delivered the installer, focused tests
and installation documentation on the isolated upgrade branch. The parent
checkpoint is `1038706243f0e6838459ca06345882fe3434d381`; no controller files were
changed or installed. It implements the following required invariants, with the
later topology repair/review and remaining evidence/live gates detailed below:

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

The parent independently passed **43 cases per ABI** (Python 3.11.16 and 3.14.7)
on both the delivered snapshot and final committed source, with pre-import
native/network/subprocess tripwires, disposable state and unchanged-source hashes.
A separate snapshot using the newer revocation-safe controller also passed the
same 43 cases per ABI. A parent-owned real first-install/fresh-stage entry test
failed on the baseline installer with `bounded upgrade API missing` on both ABIs
and passed on the delivery. The parent did not independently replay every
intermediate child repair. Changed-file Ruff and whitespace checks passed.
Focused source reviews `deleg_aa04d048` found **one supported-scope blocker**:
the default dependency checker rejects the required legacy gateway child. The
selected agent command runs `hermes_cli.stderr_timestamp`, whose direct Python
child runs `hermes_cli.main gateway run --external-supervisor`. The child's argv
is neither selected service's full argv and its PID is not the installer, so
`install_production_native.py:337–345` refuses it as an opaque interpreter before
the first upgrade journal. The parent inspected the release builder and stderr
wrapper source and hash-matched the reviewed installer/tests/builder to the
checkpoint. A separate parent-owned default-checker probe on **both Python ABIs**
passed with the earlier parent-only census fixture and failed when only the exact
generated gateway-child record was added. Failure occurred before journal creation;
root receipt, app inode and legacy selector/plists remained unchanged. These are
real disposable filesystem operations with synthetic OS observations, not live
process evidence. The earlier 43-case green suite missed this topology.

Repair `deleg_daa86bb8` delivered only the isolated installer, focused tests and
installation documentation. It is committed as
`3b04d5486898d4d865b81145fb64ed29fea9d278` on the upgrade branch; no controller
files or installed artifacts changed. Admission carries the actual loaded-job
observation into the census. The sole supported gateway child must bind exact
argv/executable and UID to the selected parent's stable PID/start identity;
reparenting, identity drift, replacement, duplicate children, unknown observations
and arbitrary descendants refuse. Self admission now requires the actual
installer PID/current UID/current interpreter and a direct absolute script
invocation, optionally `-B`, rather than an argv token merely naming the script.

The parent hash-matched the delivered snapshot and independently replayed its
original two-case probe against the unchanged `1038706243` installer on both ABIs:
the parent-only control passed, while adding only the generated child produced
the exact opaque-interpreter rejection before the first journal. The repaired
installer passed both probe cases. The expanded suite passed **48 tests per ABI**
(Python 3.11.16 and 3.14.7), both on the frozen delivery and final committed source:
20 upgrade, 12 installer and 16 permitted stage cases. New coverage uses the
actual default checker with the generated parent/child topology and installer
self PID, including ownership loss after upgrade, recovery and postreturn journals.
Two non-launcher subprocess stage cases remain deliberately excluded.

A separate disposable overlay with main's current return/revocation controller
also passed **48 tests per ABI**; this is fixture compatibility, not real chained
return evidence. Native/network/subprocess/file-scope tripwires remained active;
only the inspected synthetic launcher check was allowed. Source hashes stayed
stable and changed-file Ruff/diff checks passed. Parent evidence:
`verity-upgrade-topology-verified-n4g9pmeh/receipt.json` under configured scratch.

The earlier reviewers found no additional supported-scope blocker in immutable
provenance, observed-state recovery or the postreturn digest interface they
inspected. Both focused repair reviewers in `deleg_e0c610b8` found no concrete
supported-boundary blocker. The parent inspected the cited authority, generated
wrapper/child, self-invocation, legacy-restore and mutation-edge paths and matched
reviewed executable/test inputs to the prior tested snapshot and repair commit
`3b04d5486898d4d865b81145fb64ed29fea9d278`. Together with retained old-red/new-green
evidence, this closes the original topology rejection **offline**, not live
compatibility or full deployment acceptance.

The assigned test-only evidence gaps from `deleg_8384638f` are now closed offline.
Only the focused upgrade test file changed: three existing invariant methods now
check the entire disposable artifact arrangement, bytes/modes/owners/inodes,
receipts and mutation-call history immediately after refusal, before fixture
repair/recovery. They also cover malformed self observations and reobservation
drift, retaining the actual default checker. The parent inspected these paths,
matched runtime/test bytes, and independently passed **48 tests per ABI** on
Python 3.11.16 and 3.14.7 with the unchanged offline guard and two stage exclusions.
Against the same disposable delayed-refusal mutant, the original two methods
passed but the strengthened two failed at immediate-state assertions on each ABI
(two failures, zero errors). This validates the assertions, not a product defect;
no production implementation changed. Evidence is retained under configured
scratch at `verity-upgrade-evidence-parent-sdpxsr4y/receipt.json` with frozen hashes,
exact commands/logs and `parent-inspection.json`. The initial parent result parser
miscounted repeated traceback text; it was corrected and all six runs repeated.
Earlier 48-test passes remain historical and do not retroactively prove these
new assertions.

The new lifecycle fixture includes the installer self PID, but its argv and
identity remain synthetic. Real `KERN_PROCARGS2` readability for every
system-owned PID and direct CLI compatibility remain unverified, and inaccessible
or changing processes must still refuse. No live census or production operation
was attempted. The earlier source-review closeout was documentation-only; the
subsequent test-only verification above is separate evidence, not live acceptance.

The delivered receipt contract keeps **original baseline provenance** distinct
from **current deployment provenance**, with explicit root and committed-upgrade
pins. The future controller must produce a verified `return-retained-baseline`
transaction containing both `baseline_sha256` and `upgrade_sha256`. The installer
tests synthesize that future record; the real chained return is **not implemented
or tested**. Current-controller compatibility does not close this gap. No copied
historical fields, recursive chain lookup or implicit latest receipt may substitute.
The policy and topology repairs are source-reviewed and the assigned immediate-
mutation test coverage is verified; actual chained-return integration remains open. Fresh
staging/signing, install-only replacement, census admission and live verification
remain separately gated. No live upgrade, recovery, restore or cutover was executed
for this checkpoint.

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
changed-file Ruff passed. Focused source-only re-review `deleg_41bf0942` is
complete: failure-event parsing, encoded receipt admission and pre-GO validation
are **bounded clear**. The parent independently matched the reviewed implementation,
tests and relevant frozen helpers to committed `3100a4f9d1` and the successful
124-test-per-ABI snapshot, then inspected the cited decision paths. These three
offline review findings are closed for that snapshot, not established as live OS
behavior. The first-signal finding is closed offline by the later bounded
repair and review detailed below; live acceptance remains open.

The fixes accept only validated failure-only host records, latch the first signal
through reconciliation, bound actual encoded receipt envelopes, and move full
inventory validation before bootstrap. A 20-second admission interval and fixed
bounded point-of-use checks replace the after-ready full traversal. Its temporal
sealing limits are explicit in `PRODUCTION-CONTINUITY.md`; it is not an atomic
freshness or hostile same-UID guarantee.

**Both teardown findings are closed offline within the documented signal bound.**
The original defects were a first signal during caller-handler restoration leaving
a failed return but durable success without an invalidator, and a raising SIGINT
caller escaping partial restoration with SIGTERM still bound to the transaction.
Repair `deleg_f2a0fb07` delivered only the three continuity files. The parent
independently replayed both regression methods against unchanged `3100a4f9` code:
**20 assertion failures, zero test errors on each ABI**. This now includes executed
proof of the partial-restoration defect, not only source inspection.

The repair briefly masks SIGINT/SIGTERM after the complete reconciliation pass,
restores caller handlers, and uses one pending-signal snapshot as the explicit
terminal boundary. It restores the caller's mask and dispositions. A new immutable
`settled-REPORT` decision and `report_status()` distinguish provisional reports
from authoritative results, including success-report/invalidator double faults.
Invalidators name their exact report; later independent recovery is not invalidated.
Signals after the decision belong to the caller. This is a synchronous main-thread
POSIX bound, not arbitrary-thread masking, repeated-signal resilience or a hard
filesystem timeout; see `PRODUCTION-CONTINUITY.md`.

The parent's frozen repaired snapshot passed **131 tests on Python 3.11.16 and
3.14.7**, preserving all 124 prior fixtures and adding seven regression methods.
Delivered hashes matched; source/snapshot bytes stayed stable; changed-file Ruff
and diff checks passed. Receipt: `verity-continuity-settlement-parent-f7nwdsbm/receipt.json`
under configured scratch. Native/network/subprocess tripwires stayed active with
only inspected disposable fixture child commands allowed. Both source-only
reviewers in `deleg_318e8c97` found no supported blocker in signal ownership,
handler/mask restoration, or durable report semantics. The parent independently
inspected the cited reader, exit, run/recover/CLI and regression paths, and
hash-matched reviewed/tested inputs to repair commit
`25045eafd154af00a05b1b453f41413b63f9b12e` and the current checkout. These findings
are closed for that bounded offline implementation, not for live OS acceptance.

The closeout only qualifies documentation: caller-blocked signals are not
transaction-consumed, but restoring caller `SIG_IGN` may discard them. No runtime
or test bytes changed, and no additional test execution is claimed. The terminal
reader is not a full matrix validator; the CLI uses the settled in-memory return
value, while real durable-consumer/controller integration remains absent.
Concurrent signal consumers, repeated interrupts, failing signal syscalls, fatal
signals, hard filesystem timeouts and post-decision caller behavior stay outside
the contract. No live continuity preparation or execution was performed or
authorized by this source-review closeout; frozen host/base probes and production
artifacts remain unchanged.

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

The narrower follow-up (`deleg_e839d257`) delivered a private, explicitly local,
settled-session-only consumer. It is committed in the WebUI fork as
`f7fd6ed7dc7f0faf45fa1c7e66363009a19e609d` on
`feat/verity-restart-continuation`. The parent independently passed **101** focused
and neighboring tests on Python 3.11.16 through the repo runner, then repeated
that result on the committed HEAD with unchanged source hashes and verified
imports from the intended worktree. The original baseline fails the missing
consumer assertion. Change-scoped Ruff passes; whole-file Ruff has 24 unchanged
baseline findings, not an unconditional clean report.

The gate exercised real `_start_run`/legacy adapter/stream-start paths with fake
workers, durable file claims and worker-entry receipts, uncached Session loading,
ordinary admission orderings, process-reinstantiated claims and the extracted
server startup helper. Disposable state and an explicit offline guard were used;
the unrelated autouse HTTP-server fixture was disabled. **Full server startup,
controller integration and live same-session continuation were not exercised.**
The two focused reviews (`deleg_98cbabad`) found **three supported-scope
blockers**. The parent independently inspected the cited paths and matched the
reviewed consumer, routes, server, streaming and test bytes to committed
`f7fd6ed7dc7f0faf45fa1c7e66363009a19e609d`. The parent subsequently replayed all
five failing regression cases, as recorded in the repair checkpoint below.

- Receipt failure after Stop can strand cancellation settlement. The executing
  receipt wrapper calls launch cleanup and returns without entering the worker
  (`api/post_restart_continuation.py:272–279`). Stop registers a `worker`
  participant when it sees the published stream (`api/streaming.py:16189–16192`),
  but launch cleanup (`api/routes.py:24183–24228`) does not retire it. The ordinary
  worker's pre-start retirement is bypassed. Test both retirement orderings with
  actual cancellation bookkeeping, including pending/owner/fence cleanup.
- `/goal` kickoff is not guarded at its entry (`api/routes.py:25465`). It can
  observe idle, then mutate model signature and goal state after continuation
  validation but before reaching the guarded stream-start helper. Cover both
  winners with real entrypoints/fake workers and preserve control-only commands.
- The startup consumer is not owned by server shutdown (`server.py:603,660–702`).
  A request waiting for terminal proof can claim and launch while graceful
  shutdown is already cleaning up. Merely checking an event between polls is
  insufficient: fence the claim against shutdown and settle an admission that
  wins first before owner teardown. Do not block on locks/joins in signal handlers.

Repair `deleg_6c664622` delivered only the five authorized consumer/routes/server/
test/documentation files; `api/streaming.py` is unchanged. Parent checkpoint
`fb41e6625dddf9d023724f21dccd25d3720032b5` is committed and pushed to the WebUI fork,
with exact remote SHA verified. It adds worker-participant retirement under the
stream-detachment lock, early goal admission, and an owner claim/close boundary
with retained consumer stop/join in `server.main()` teardown.

The parent independently passed **148 tests with 5 deliberately deselected**
native-Agent goal cases, then **9** neighboring launch-cleanup/settlement tests.
The combined gate on committed HEAD passed **157 tests, 5 deselected**, on Python
3.11.16 through `./scripts/test.sh`. Source hashes remained unchanged and imports
resolved to the intended worktree; no Agent was loaded. Changed-file lint has
24 baseline / 24 final findings with no additions; whitespace checks passed.

A test-only loader compiled the exact pre-repair three-module Git blobs at their
original paths and reproduced **five expected failures**: two leaked Stop worker
participants, two goal admission failures, and actual-main teardown observing a
live consumer. Product files were not temporarily replaced. This is source-code
regression replay, not a baseline deployment/release-identity test. The offline
guard blocks native loading, unexpected subprocesses, listening and outbound
connections; its initial overblocking of conftest's import-time ephemeral
loopback port reservation was corrected only in the parent harness. All test
state was disposable and the unrelated autouse HTTP server remained suppressed.

Actual imported `server.main()` now has offline wiring tests with fully stubbed
startup dependencies and fake HTTP, including both shutdown/claim orderings.
Admission-winning shutdown waits for claim/launch settlement, **not** model
completion or worker-entry receipt. Full dependency startup, actual signals,
controller proof publication and live same-session restart remain unproved.
Both focused source-only reviewers in `deleg_419f8eb7` found no concrete blocker
within the single-owner, settled-session, explicit-local legacy scope. The parent
inspected the cited cleanup/Stop, goal-admission and owner claim/close/teardown
paths and hash-matched executable/test inputs to the frozen reviewed snapshot,
parent test evidence and committed repair `fb41e6625dddf9d023724f21dccd25d3720032b5`.
The sole frozen-documentation delta was the subsequently added parent verification
section, not a changed contract. This closes all three original findings
**offline**, not full startup, deployment or live continuation. Parent evidence is
retained at `verity-resume-repair-parent-2mcydzbi/parent-final-receipt.json` and
`review-closeout.json` under configured scratch; the earlier checkpoint is unchanged.

Evidence limits remain explicit: cleanup-before-Stop-registration is supported
by source interleaving rather than a dedicated barrier, and neighboring successor
tests are not a fully concurrent successor launch. Captured callbacks/fake HTTP do
not prove actual signal delivery or real pre-serve shutdown. If startup raises
before serving after a shutdown helper starts, that daemon helper can remain in
`httpd.shutdown()`; main still closes/joins the consumer before teardown. Helper
termination is not established on that exceptional path. An admitted worker can
enter after consumer join/HTTP teardown; an absent entry receipt never authorizes
replay. This closeout is documentation-only and claims no new test or live run.

Gateway, runner, non-WebUI and unknown ownership refuse. Capture is permitted only
after settlement; persisted pending/active work refuses. HTTP, server-wakeup and
goal kickoff participate in the reviewed shared admission within that scope.
Ambiguous durable claims never authorize replay.
Unsupported external writers remain outside the contract. No source-only audit,
unconsumed request or standalone mocked state machine satisfies the cutover
condition.

A parent read-only metadata check found the initiating session open, sourced from
WebUI, in the requested profile/workspace, with an active stream and pending turn.
That is not idle/admission evidence and does not establish the effective backend;
missing explicit backend settings are not proof of local ownership. No live
request was written, no API called, and no turn injected.

The remaining integration is a durable controller job that publishes the private
consumer protocol (`deployment.json`, immutable `request.json`, and terminal
operation proof pinned to the new owning PID/start time). The existing controller
does not yet implement it. Bind operation, initiating session, profile, workspace
and expected release; preserve the consumer's pre-worker admission identity and
reconcile it against the worker-entry receipt. Duplicate triggers must resolve to
the same disposition, busy work must remain pending, and uncertain dispatch must
stop for reconciliation rather than repost. The local-only path rejects a
rotated/sealed session rather than following an unverified descendant or reopening
a parent. Do not weaken authentication or copy browser credentials to make this
work.

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
