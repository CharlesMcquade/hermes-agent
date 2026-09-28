# Schema-2 native install, one-hop upgrade, and retained-artifact recovery

`install_production_native.py` supports bounded first-install/restore and a single
retained install-only upgrade, **not activation**. Independent review and separate human approval are required
before real use. Offline tests are not evidence of real Apple signing, permission,
live process identity, or production compatibility.

## Preconditions and explicit approval

Use a reviewed, complete stage produced by `stage_production_native.py`. Both
`HOME/Applications` and `BASE/control-versions` must already exist, be canonical,
operator-owned and not group/world writable. The exact final destinations are
`HOME/Applications/Verity.app` and `BASE/control-versions/CONTROL_ID` from the
stage report; neither may exist. `--home` is explicit (production uses the actual
operator home; tests use disposable homes). It does not redirect production
state by itself. `BASE/control.lock` must already exist with safe ownership/mode
and canonical ancestors, for **both** install and restore. The installer never
creates, replaces, or chmods that shared lock. Missing or group/world-writable
locks are a refused prerequisite, not an invitation to repair live state.
This is an upgrade to an established schema-2 controller, not lock provisioning.

After approval only, the interface is:

```text
python -B install_production_native.py --base BASE --home HOME --stage STAGE --approve-install
python -B install_production_native.py --base BASE --home HOME --approve-restore
```

The install command has now run with operator approval; restore has not. Installation executes
only read-only codesign verification, never signing, app execution, launchctl,
selection, job reload/restart, or service-manager changes. Existing candidate
files remain untouched. It uses the existing `control.lock`, `atomic_write`,
`save_json`, and `verify_stage` contracts.

## Receipt and recovery

Before copying any artifacts, the tool saves `BASE/native-install-receipt.json`:
original selected manifest/plist/wrapper bytes, actual modes and owner IDs at
the before-write boundary, replacement bytes, final destinations, and stage
report. SHA-256 detects accidental receipt corruption, not malicious edits by
the same account. Receipt phases record preparation, artifact installation,
each wrapper publication, installation completion, and restoration. A failed
write may have renamed successfully before reporting an fsync error; restore
accepts either original or replacement wrapper bytes, never arbitrary drift.

The five copied control modules are installed with mode 0444 in a unique 0555
version directory; the signed app preserves staged modes. Wrappers are published
only after final inventory and signature verification. They import the installed
absolute version path, not the mutable experiment tree. Actual wrapper modes
are preserved. No existing app/version is overwritten.

A present install receipt blocks a second install even when terminal. Missing,
malformed, corrupt or foreign receipts cannot authorize restoration. An
unresolved activation transaction blocks both operations. Restore is repeatable
following a partial restore, but never resumes forward installation.

Restore requires exact unchanged legacy selector/plist bytes, owners and modes;
terminal/absent activation state; and affirmative live dependency evidence.
The default live check inspects loaded legacy job definitions and exact kernel
PID/UID/PPID/executable/argv identities twice. It performs read-only launchctl
**print** through the existing Host adapter; it never loads/reloads jobs. Unknown,
unavailable, changing or native-dependent processes fail closed. Most fault tests
substitute a fixture dependency adapter. The focused wiring test retains the
default checker and actual Controller definitions/loaded logic, mocking only
Host job/process observations; no offline test executes launchctl commands.

Rollback restores **only original wrappers**. App/control directories, including
partial copies, and the receipt are retained with status
`restored_artifacts_retained`; they are never recursively deleted or reused.
Post-cutover selector changes prevent rollback even if a live adapter would
otherwise return true. A later manual, separately approved reconciliation must
resolve retained artifacts before another first install.

## Approved install-only execution

After the review gate cleared, the operator replied “go” to install-only and the
bounded temporary same-identity permission-test proposal. This does not authorize
selection, service restart, or cutover. The parent ran the reviewed installer from
`2cf0201f689070e98e7af1d4baf4020a2b609f0b` with `--approve-install` against the
verified stage. It returned `installed`, `selected_release_unchanged:true`,
`activated:false`.

A separate read-back of the real installed targets verified:

- `~/Applications/Verity.app`: exact candidate inventory, canonical metadata,
  signed settings, launcher hash and strict production-leaf-pinned signature;
- `control-versions/verity-native-v1`: all five module hashes and control receipt,
  0444 files in a 0555 directory; all four wrappers match exact expected bytes
  and retain their original modes and ownership;
- durable `native-install-receipt.json` phase `installed`, valid checksum,
  exact retained selector/plist/wrapper baseline;
- both candidate native definitions match the staged proposals, and the selected
  source/runtime inventories validate without application imports or reading
  credential contents;
- legacy selected manifest, persisted plists, loaded job definitions and kernel
  process identities remain unchanged; WebUI health remains `ok`.

Passive LaunchServices registration subsequently resolved `com.charles.verity`
to the exact installed app path. Registration did not execute the app or prove
permissions. No native service role, production restart or restore was executed.
The native candidate remains unselected. Permission testing and post-cutover
actual-descendant proof are separate gates; this is not cutover readiness.

## Historical parent verification (before installation)

Parent runs passed 75 experiment and 71 controller tests on Python 3.11; Python
3.14 passed 67 experiment and 71 controller tests, excluding eight signer tests
requiring unavailable cryptography. The installer class was selected explicitly
to avoid counting the imported staging class twice. All 10 installer methods
passed, including real file publication/restoration within disposable fixtures.
Changed-file Ruff and Git diff checks passed.

The parent separately invoked only `no_live_native_dependency` against the current
legacy pair. It returned true after real read-only loaded-job/kernel-identity
checks. No install/restore function or launchctl mutation was called. This proves
that observation for that current pair, not restore success or interruption/race
coverage of the live adapter. The real production-signed stage was reverified;
final app/control installation and final-path signature verification remain undone.
Production hashes, PIDs and health remained unchanged. Install-only and
permission-test prompts have no recorded approval.

Review `deleg_6f153763`, task 1, found one lock/recovery blocker: the shared helper
can create an absent lock as 0664 under umask 0002, while subsequent restore rejects
that mode. Both entry points now require an existing safe lock before the shared
helper. The regression failed on the original implementation (`ControlError not
raised`); the corrected test verifies absence refusal before receipt/copy, unsafe
lock refusal, publication failure plus exact byte/mode restoration under umask
0002 with a preprovisioned safe fixture lock, and no lock recreation on restore.
The existing production lock passed read-only `safe()` with mode 0644; no mode or
lock changes were made.

Task 2 established no additional restore blocker but identified the default-checker
test gap. A new full-restore wiring test keeps that default and verifies distinct
cached-launcher vs selected-service identities (including the gateway stderr-wrapper
`-m` command). Per-role wrong executable/argv/PPID/UID, changed birth record, missing
PID, native cached argv and unavailable identity all refuse before wrapper or
receipt writes. These are synthetic observations, not live restore evidence.

After these changes, 77 experiment and 71 controller tests pass on Python 3.11;
Python 3.14 passes 69 experiment and 71 controller tests (the same eight signer
tests excluded). The 12 installer methods are selected once, not duplicated via
the imported staging class. Ruff and diff checks pass. Focused re-review
(`deleg_be540b83`) found no blockers in the lock/recovery fix and default-checker
test scope. It confirmed both entry points require the existing safe lock, the
regression covers the original missing-lock boundary, and the default dependency
binding plus real definitions/loaded checks are retained. This was a source-only
review, not a test rerun or live restore. Parent matched the reviewed files to
`e6d238e771d18bc270b6026e890b12c776ab4f67`. The installer review gate is clear;
real installation/restore remain unexecuted and require separate authorization.

The reviewer also noted that replacement receipt entries are not independently
decoded/regenerated when a wrapper already equals its validated original. No unsafe
restore consequence was established in this scope: only validated original bytes
are written. The checksum is corruption detection, not authentication; do not treat
it as authorization against a malicious same-account receipt rewrite.

## Verification and limits

Run from `experiments/verity_identity` with supported Python 3.11, isolated
`HOME`/`HERMES_HOME`, clean `PYTHONPATH`/`PYTHONSAFEPATH`, and scratch `TMPDIR`:

```text
python -B -m unittest test_install_production_native.InstallTests -v
python -B -m unittest test_stage_production_native -v
```

Tests cover unchanged selection/plists/candidate, real independent synthetic
source/runtime directories, installed launcher `--check` after removing the
stage, wrong paths/drift, unresolved transactions, existing destinations,
symlink rejection, extra controls, missing/malformed receipt, post-cutover and
unknown live dependency refusal, failure after each wrapper rename, partial
artifact publication and interrupted restore. They verify exact restored bytes
and modes. Signature/compiler behavior is an adapter fixture, not real signing.
The synthetic check validates tiny fixture inventories/runtime executability;
it does not import application modules or read credential files.

Limitations: read-only modes are not OS immutable flags; the owning user can
change them. The shared advisory lock coordinates participating controllers,
not arbitrary same-UID filesystem writers or manual launchctl operations.
Canonical/owner/mode checks reject ordinary symlink escapes but are not a
hostile same-account filesystem sandbox. Directory copy is deliberately not an
atomic bundle rename; incomplete destinations are retained, never selected by
this tool. At that first-install checkpoint there was no installer upgrade path;
the bounded source-only extension below supersedes only that limitation. There is
still no automatic cleanup, ACL/xattr backup, permission grant, live restart test,
or resume-forward operation.
The child did not test default live dependency inspection; the parent read-only
check above supplements that limitation. Real final-path codesign and installation
remain untested. The installer itself is an operator-side review-required tool;
only installed control execution is independent of the experiment source.
The subsequent install-only execution above supersedes the earlier final-path
untested status, not the remaining live restore and permission limitations.

## Bounded one-hop upgrade (source and offline fixtures only)

This is one original installation to one fresh staged version, not a release
manager. The original `native-install-receipt.json` must still say `installed`;
its exact file SHA-256 is supplied explicitly. The legacy selector and both
plists must match its retained bytes, owners and modes. All four current wrappers
must be its regenerated v1 replacements. Partial/restored installations, unsafe
or dangling paths, unresolved activations, existing new destinations, and any
previous upgrade journal/commit refuse. No second hop or automatic latest-version
selection is supported, even after successful recovery.

The separately retained original stage is required because the root receipt
contains the candidate digest, not the complete signed-app inventory. Both stages
are reverified and their reports hash-linked. The fresh stage must have saved the
v1 replacement wrappers as rollback inputs, while retaining exactly the root
legacy selector/plists, service/runtime/environment configuration, signing
requirement and bootstrap interpreter/environment. Its signed launcher hash must
match its newly versioned wrappers. No controller, stager or native host source
is changed by this extension.

After independent review and separate approval only, the operator interface is:

```text
python -B install_production_native.py --base BASE --home HOME --stage V2_STAGE --original-stage V1_STAGE --root-sha256 ROOT_SHA256 --approve-upgrade
python -B install_production_native.py --base BASE --home HOME --root-sha256 ROOT_SHA256 --recover-upgrade
python -B install_production_native.py --base BASE --home HOME --root-sha256 ROOT_SHA256 --upgrade-sha256 UPGRADE_SHA256 --restore-upgraded-wrappers
```

These are interface descriptions, not authorization or executed production
commands. Use the reviewed installer by its absolute path. The upgrade copies
new controls to the fresh canonical `BASE/control-versions/ID` (0444 files,
0555 directory), and a fresh app to `HOME/Applications/Verity.upgrade-v2.app`.
It verifies the copies, then renames the **original app itself** to
`HOME/Applications/Verity.upgrade-v1.app` before renaming v2 to `Verity.app`.
The old app's inode/device, bytes, ownership and exact directory/file modes are
retained; rename also preserves the original inode's metadata rather than
reconstructing a historical signed app. Final-path signature verification occurs
before any v2 wrapper publication. Wrappers are replaced individually with their
actual original modes. Root receipt, original stage and original controls are
never rewritten or deleted; the old first-install restore refuses once an upgrade
journal or receipt exists.

Each mutation group has a durable journal intent before it, and each app rename
and wrapper publication has its own intent. File contents and destination
directories are fsynced. The two same-filesystem app renames are **not one atomic
swap**: there is a recorded gap with no `Verity.app`. This is permitted only with
legacy selection and affirmative dependency absence. The shared `control.lock`
is advisory: it does not prevent arbitrary same-UID writes or manual launches.

The upgrade/recovery/postreturn default checker supplements the existing loaded
legacy-job/kernel-identity check with `proc_listallpids` and repeated kernel
identities for every PID except kernel PID 0 and launchd PID 1, regardless of UID.
It rejects installed app/control/wrapper references and opaque Python interpreters
other than the verified loaded selected parents, their one supported direct gateway
child, or this directly invoked installer.
Unknown, inaccessible, exiting or changing processes refuse; there is no retry
that silently discards an uninspectable process. This deliberately conservative
check may refuse on a busy or restricted machine. It is not an OS launch barrier
or a proof against arbitrary injected code. No real census/native API was run in
this task; only adapter fixtures exercise this path. Absence and exact baseline
checks repeat before/after journal preparation and at publication boundaries.

### Immutable provenance and later controller interface

`BASE/native-upgrade-journal.json` is mutable, operator-owned, mode 0600, bounded
to 4 MiB. `BASE/native-upgrade-receipt.json` is an exclusively published, never
rewritten committed record, mode 0444, with the same bound. Read-only mode is not
an immutable filesystem flag. Both use this envelope:

```text
{ "payload": {
    "schema_version": 1,
    "kind": "one-hop-native-upgrade",
    "phase": JOURNAL_PHASE_OR_committed,
    "plan": {
      "root_sha256": ROOT_RECEIPT_FILE_SHA256,
      "original_stage": ABSOLUTE_RETAINED_STAGE,
      "new_stage": ABSOLUTE_RETAINED_STAGE,
      "original_report": ORIGINAL_STAGE_REPORT,
      "new_report": NEW_STAGE_REPORT,
      "original_stage_sha256": ORIGINAL_REPORT_FILE_SHA256,
      "new_stage_sha256": NEW_REPORT_FILE_SHA256,
      "v1_tree": TREE_RECORDS,
      "v2_tree": TREE_RECORDS,
      "v1_identity": [DEVICE, INODE]
    }
  }, "sha256": SHA256(stage.encoded(payload)) }
```

`stage.encoded` is sorted, two-space-indented JSON with a trailing newline.
Tree entries are relative paths (including `.`), each with exact `mode`, `uid`,
and `sha256` (null for directories). Reports bind selected/candidate/control and
rollback hashes. Destinations are reconstructed from explicit BASE/HOME and
validated control-version names; tree keys never drive writes. SHA-256 detects
corruption, not a malicious same-account replacement. The operator must pin exact
**file** bytes externally: the root receipt remains baseline authority; the
committed upgrade receipt, pinned separately, is current deployment authority.

The source controller now accepts `--return-upgrade-sha256` with the existing
explicit root-baseline pin, validating both immutable receipt lineages. It uses
the new report/candidate/controls/wrappers for current-deployment validation and
the original root receipt for target legacy bytes. See the exact-return contract
in `scripts/production_control/README.md`. No recursive lineage or auto-latest
lookup is permitted. A successful verified return produces:

```text
phase = verified
reload = true
operation = return-retained-baseline
baseline_sha256 = ROOT_SHA256
upgrade_sha256 = UPGRADE_SHA256
```

The postreturn wrapper operation requires that checksummed transaction, exact
legacy bytes/modes/owners, both explicit receipt pins, intact retained artifacts,
and repeated dependency absence. It preserves the transaction bytes during the
operation and restores only the root's exact legacy wrapper records. Merely
remaining legacy-selected after install-only upgrade does **not** authorize it.
The original upgrade unit fixtures still use synthetic completion records for
isolated installer tests. Separate `test_upgrade_return_composition.py` now
executes the full staged/installed-module return sequence and supplies the real
verified transaction to this operation. Parent replay passed this composition
within a frozen 131-test aggregate on both Python 3.11.16 and 3.14.7. Signature,
process/health and dependency-absence observations are explicit fake adapters;
focused source-only review `deleg_66b6b131` is bounded-clear, with reviewed source
matched to current bytes by the parent. This closes neither the live maintenance admission
problem (`MAINTENANCE-CONTRACT.md`) nor native activation, same-session resume,
permission, real signature or live upgrade gates. The installer is unchanged.

### Recovery and verification evidence

Recovery reads observed app identities and wrapper bytes, not journal phase alone.
Before commit, it retains v2 at the fixed pending path, renames the original v1 app
back and restores v1 replacement wrappers, never resumes forward installation.
Interrupted recovery is explicit and repeatable only for recognized arrangements.
Unknown bytes, partial artifact copies or malformed preparation records are retained
and refused for manual reconciliation; the tool never deletes or repairs them.
After commit, recovery verifies the complete committed app/control/wrapper pair,
not a blind rollback. A commit rename that succeeds before its fsync reports an
error is recognized on subsequent recovery. Postreturn wrapper restoration is a
separate repeatable operation and does not alter either immutable receipt.

TDD first failed on the missing bounded-upgrade API. Further red/green cases
covered legacy restore rewriting the root after upgraded restoration, missing
final-path verification, mutable commit mode, unknown journal phase, independent
stable-wrapper controller dependencies, absent revocation checks, and accepting
legacy-but-never-returned state. One initial fault fixture matched copied control
filenames rather than stable wrapper destinations; it was narrowed to exact paths
before reporting wrapper fault coverage.

The offline suite covers real first-install -> fresh-stage -> upgrade composition,
all pre/post journal boundaries (`copy_controls`, `copy_app`, `retain_v1`,
`publish_v2`, four wrapper publications, `commit`), both app rename-success/error
boundaries, all four wrapper rename-success/error boundaries, commit publication
success/error, failed final signature adapter, baseline drift after journaling,
interrupted v1 recovery and interrupted legacy-wrapper restoration. Original
receipt/stage/control bytes and exact original app inode/modes are checked.

Verification uses stdlib unittest with explicitly selected classes, not repository
pytest discovery. Source/configuration hashes are frozen before/after each run;
HOME/HERMES_HOME/HERMES_WEBUI_STATE_DIR/TMPDIR are disposable per subprocess,
PYTHONPATH/PYTHONSAFEPATH are removed, and no shared environment is exported.
Before test imports, subprocess/native/network tripwires are installed. Only the
inspected installed synthetic launcher `--check` is allowed as a subprocess, after
checking exact argv, disposable environment, copied control bytes and empty
application-probe/environment-file lists. Compiler/signature/kernel observations
are fake adapters. The neighboring stage environment-probe and module-import
subprocess cases are explicitly excluded; this task authorizes only launcher
fixture subprocesses. Both requested ABIs are run. No real compile, signing,
native process inspection, launchctl, network, production state, credentials,
commit or push is part of this verification.

Final isolated runs passed **43 cases on each requested ABI** (Python 3.11 and
3.14): 15 upgrade methods with fault/adversarial subcases, all 12 installer
methods, and 16 permitted neighboring stage methods. Each run verified unchanged
hashes for a 61-file set comprising experiment/control Python files and the
selected configuration. The two excluded stage methods are
`test_compiler_uses_only_stage_local_scratch_and_clean_environment` and
`test_snapshot_modules_import_without_application`. Changed-file Ruff and Git
whitespace checks passed. The parent independently reran **43 cases per ABI**
on a frozen delivered-source snapshot with pre-import native/network/subprocess
tripwires and disposable state. A parent-owned entry regression composed the real
first install and fresh stage: both ABIs failed on the baseline installer with
`bounded upgrade API missing` and passed with the delivered installer. This is an
API-entry regression, not independent replay of every intermediate child fix.

The parent also reran the same **43 cases per ABI** on a separate snapshot with
the newer revocation-safe controller, retaining the delivery's installer and
stager bytes. That is compatibility evidence, **not** a chained controller-return
test: postreturn fixtures still synthesize the future completion transaction.
Source hashes stayed unchanged, and independent changed-file Ruff and Git
whitespace checks passed. Two focused source-only reviews are pending. Deployment,
real process-census usability, upgraded controller return integration and all live
gates remain outstanding.

### Legacy gateway topology admission repair (offline only)

The generated legacy agent command is a `hermes_cli.stderr_timestamp` parent
which starts the exact `python -m hermes_cli.main gateway run
--external-supervisor` direct child after `--`. The earlier broad census refused
this healthy child as an opaque interpreter. A regression with both selected job
parents, that child, and the installer self PID failed before the upgrade journal
on Python 3.11.16 and 3.14.7. It composes real disposable first-install and fresh
stage filesystem operations; kernel and signature observations remain fixtures.

Admission now retains the existing loaded-job observation (controller,
definitions, jobs and complete parent identity records) throughout each census.
Selected argv alone grants no exemption. The sole supported child must match the
exact generated wrapper shape and child argv, parent PPID, UID and executable,
and cannot predate its parent. Multiple matching children, unexpected children
of either selected parent, and gateway grandchildren refuse. Loaded-job ownership
and all identities are rechecked against that same observation; census changes,
unreadable identities and independent control/native references still refuse.
No arbitrary descendants or unknown system-owned processes are silently ignored.

The self exemption requires the actual installer PID, current UID and resolved
interpreter executable, with argv beginning exactly with the current interpreter
and absolute installer path (optionally `-B` between them). Another script merely
mentioning that path, a different interpreter, `-c` or `-m` invocation is not an
exemption. Other interpreter flags and relative installer paths conservatively
refuse. This is cooperative observation, not an OS launch barrier or protection
against same-account injected code.

The expanded suite retains the default dependency checker for upgrade, recovery
and synthetic postreturn restoration. It covers unowned/reparented children,
parent replacement and birth drift, child UID/executable/birth drift, missing or
unreadable records, census changes, duplicate children, unexpected descendants,
independent interpreters/control references and narrow self invocation positives
and negatives. Every upgrade journal boundary is followed by injected topology
loss; recovery and postreturn journal boundaries inject selected-job ownership
loss and prove refusal before further wrapper writes. Fixture-only repair then
allows explicit recovery/restoration; it is not a production reconciliation.

The verification runner is an unchanged copy of the previously inspected guarded
runner: disposable HOME/HERMES_HOME/state/TMPDIR, frozen source hash checks,
pre-import native/network/real-file tripwires and only the inspected synthetic
launcher subprocess exception. Both ABIs run the permitted neighboring installer
and stage cases. Real all-PID KERN_PROCARGS2 readability, system-process census
usability, native activation, signatures and controller-return integration remain
unverified/live gates. The postreturn completion transaction is still synthetic.

### Independent topology repair verification

The parent matched every delivered snapshot hash and independently froze the
repair. Its original two-case topology probe was replayed on both Python 3.11.16
and 3.14.7 against the unchanged `1038706243` installer: the parent-only control
passed and the exact generated gateway child produced the expected opaque-
interpreter exception before any journal or artifact mutation. With the repaired
installer, both probe cases passed on both ABIs.

The expanded permitted aggregate independently passed **48 tests on each ABI**:
20 upgrade, 12 installer and 16 stage cases. The inspected guard was unchanged;
pre-import native/network/subprocess and file-scope tripwires stayed enabled, with
only the exact disposable synthetic-launcher check permitted. The two non-launcher
subprocess stage cases remain deliberately excluded. Source hashes stayed stable,
and changed-file Ruff plus `git diff --check` passed.

A separate frozen overlay using the return/revocation controller from main
checkpoint `25045eafd154af00a05b1b453f41413b63f9b12e` also passed **48 tests per ABI**.
This establishes fixture compatibility, not an actual chained controller return.
The parent's evidence is `verity-upgrade-topology-verified-n4g9pmeh/receipt.json`
under configured scratch. Both focused source reviewers in `deleg_e0c610b8`
found no concrete supported-boundary blocker. The parent independently inspected
the retained observation, exact generated topology, self invocation, neighboring
legacy restore and journal/mutation call sites, then matched reviewed runtime/test
inputs to the tested snapshot and committed repair
`3b04d5486898d4d865b81145fb64ed29fea9d278`. The original required-gateway-child
rejection is closed **within the reviewed offline scope**. No compile, signing,
real process observation, live state mutation, upgrade, activation or restart was
performed by these verification runs or this source-review closeout.

The review identified evidence gaps, not demonstrated runtime failures. The
then-current journal tests established eventual refusal/recovery but lacked
immediate no-copy/no-rename/no-write assertions, app arrangement/inode snapshots
at the recovery rename boundaries, and several malformed-self/drift cases.
Test-only follow-up `deleg_8384638f` now strengthens those three existing invariant
methods without changing production source. The earlier 48-test passes remain
historical evidence; the independent strengthened-test results follow below.

The new success fixture covers self PID, while the older broad-census fixture
still does not. Both use synthetic kernel argv; neither launches the real
installer CLI. Actual all-PID readability and invocation compatibility, real
controller-return composition, matched deployment and final-identity live
acceptance remain separate gates. Source review is not permission to relax
unknown-process refusal or claim an atomic launch barrier.

### Independent test-only evidence strengthening

The parent inspected the three changed methods and two shared test helpers,
verified unchanged production installer bytes and the original offline guard,
and froze the current inputs. Assertions now run immediately at refusal before
fixture ownership is restored or recovery is attempted. They compare the entire
disposable artifact tree (existence, bytes, modes, owners, inode/device and app
arrangement), preserve root/commit/ready receipts, and record existing
copy/rename/write entry points so calls remain detectable even if later reversed.
Only the selected journal publication is allowed. The default dependency checker
remains real; malformed self birth/argv/token/UID/PPID observations and five
self-identity reobservation drifts are exercised with synthetic OS adapters.

Independent runs passed **48 tests on Python 3.11.16 and 48 on Python 3.14.7**
(20 upgrade, 12 installer, 16 permitted stage methods), with the same two staging
subprocess exclusions. Source hashes remained unchanged; changed-file Ruff and
`git diff --check` passed. All existing test methods were retained.

A controlled disposable mutant delayed refusal until after one forbidden app
rename at `retain_v1` or `recover_retain_v2`. On each ABI, both original methods
passed against that mutant, while both strengthened methods failed at the new
immediate-state assertion, before fixture repair, with **two assertion failures
and zero errors**. This is mutation-test evidence of stronger assertions, **not
an actual product defect**; the mutant never entered the repository.

Parent evidence is `verity-upgrade-evidence-parent-sdpxsr4y/{freeze.json,
receipt.json,parent-inspection.json}` under configured scratch. An initial parent
freeze stopped on the existing documentation-only review closeout; the exact diff
was reconciled before running. An initial result parser double-counted repeated
traceback text; only that orchestration parser changed before all six verification
runs were repeated. Original logs remain retained. No guard was weakened and no
production source, native API, live census, signing or service state was changed.
This closes the assigned test-only evidence gaps, not the live/integration gates.
