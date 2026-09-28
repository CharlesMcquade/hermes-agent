# Schema-2 native first install (review required)

`install_production_native.py` is a bounded first-install/restore tool, **not an
activation tool**. Independent review and separate human approval are required
before real use. Offline tests are not evidence of real Apple signing, permission,
live process identity, or production compatibility.

## Preconditions and explicit approval

Use a reviewed, complete stage produced by `stage_production_native.py`. Both
`HOME/Applications` and `BASE/control-versions` must already exist, be canonical,
operator-owned and not group/world writable. The exact final destinations are
`HOME/Applications/Verity.app` and `BASE/control-versions/CONTROL_ID` from the
stage report; neither may exist. `--home` is explicit (production uses the actual
operator home; tests use disposable homes). It does not redirect production
state by itself.

After approval only, the interface is:

```text
python -B install_production_native.py --base BASE --home HOME --stage STAGE --approve-install
python -B install_production_native.py --base BASE --home HOME --approve-restore
```

These commands have **not** been run against production. Installation executes
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
unavailable, changing or native-dependent processes fail closed. Tests substitute
an explicit fixture dependency adapter and execute no launchctl commands.

Rollback restores **only original wrappers**. App/control directories, including
partial copies, and the receipt are retained with status
`restored_artifacts_retained`; they are never recursively deleted or reused.
Post-cutover selector changes prevent rollback even if a live adapter would
otherwise return true. A later manual, separately approved reconciliation must
resolve retained artifacts before another first install.

## Parent verification (not installation)

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
Production hashes, PIDs and health remained unchanged. Independent installer review
is pending. Install-only and permission-test prompts have no recorded approval.

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
this tool. There is no installer upgrade path, automatic cleanup, ACL/xattr
backup, permission grant, live restart test, or resume-forward operation.
The child did not test default live dependency inspection; the parent read-only
check above supplements that limitation. Real final-path codesign and installation
remain untested. The installer itself is an operator-side review-required tool;
only installed control execution is independent of the experiment source.
