# Controls-only native refresh

Status: implemented and independently replayed **offline**; install-only refresh
and an isolated native rehearsal are now explicitly approved. Preparation found a
real receipt-capacity incompatibility before any installed control changes.
Focused review confirmed the lock fix, but also found that the backup validator
accepts a two-argument legacy plist lacking its launcher. Both-role regression
cases reproduce that refusal gap on each ABI; argv-shape and capacity remediation
remain in progress, alongside installed readback. The parent has now completed
the approved isolated signed native rehearsal, including restart and bounded exact
rollback; this is not production activation. Production cutover still requires
separate approval.

## Why this is different from an app upgrade

The native readiness repair belongs in the Python controller, not the signed
ServiceHost. `refresh_production_controls.py` leaves the original signed app,
its settings and inode, stable launcher wrapper, original v1 control bundle,
original native candidate, and root installation receipt unchanged. Only these
three management wrappers change:

- `restart_production.py`
- `watchdog.py`
- `approved_restart_job.py`

The new immutable six-module bundle lives at
`BASE/control-refresh-versions/NAME`. The stable launcher continues using v1.
No app pathname is replaced, so this route does not require or establish the
launch-exclusion mechanism rejected in `MAINTENANCE-CONTRACT.md`. The ordinary
app-upgrade installer and its fail-closed process census are not weakened.
There is no compiler, signer, process census, application import, service stop,
service start, or permission request in refresh staging or installation.

## Authority and stale controllers

An explicit root-receipt SHA-256 remains the authority for the original baseline.
An explicit preparation-report SHA-256 identifies the new source bundle. Under
the existing lock, installation captures the exact original terminal transaction
bytes/mode, prepares the eventual refresh receipt, and hashes its exact bytes.
It durably publishes an envelope with `schema_version: 2` and that refresh pin
**before** publishing any of the three wrappers. The contained transaction and
its checksum are unchanged. No missing-file or temporary schema-1 window exists.

The actual immutable-v1 restart and recovery paths reject an unknown transaction
schema before service control or recovery-attempt consumption. A retained old
approved job delegates to the same check. An old watchdog can still write its
`blocked` diagnostic; this is not a blanket no-writes fence. Old read-only checks
and launchers remain possible and compatible because the app and launcher are
untouched. An old operation already holding the lock finishes before refresh;
an old caller arriving after refresh observes the fence.

Refreshed runtime requires both its actual dedicated immutable directory and an
explicit matching pin. The committed receipt, complete wrappers, bundle inventory,
root lineage, unchanged artifacts and lock identity are revalidated under the
operation lock. Missing or schema-1 transactions refuse, including on a retained
refreshed object called after undo. All transaction phases preserve schema 2.
`native-control-refresh-commit.ready.json` alone does not admit runtime actions:
`native-control-refresh-receipt.json` is published last. The separate journal is
recovery evidence, not authority to invent paths or a successful activation.

The cooperative single-user model is unchanged. It does not contain malicious
same-UID/root writers. Relevant malformed, missing, drifted, or unreadable inputs
fail closed. The retained original stage is required by the current validator.

## Preparation and install-only interface

These are parameterized forms, not resolved production commands. Pin the script
and all its source dependencies, use the retained interpreter with `-B`, and
record exact canonical paths and digests in a private operation plan. Never derive
an authorization digest from an untrusted file merely to satisfy a failed check.
The flags do not themselves confer user approval.

```text
refresh_production_controls.py stage
  --stage FRESH_STAGE --base BASE --home HOME
  --root-sha256 ROOT_PIN --original-stage ORIGINAL_STAGE
  --version-name NAME

refresh_production_controls.py install
  --stage FRESH_STAGE --base BASE --home HOME
  --root-sha256 ROOT_PIN --stage-sha256 PREPARATION_PIN --approve
```

Staging does not capture authority for a future terminal transaction. Installation
captures it again under the unchanged lock. The committed refresh receipt's digest
must be independently read back and put in the unarmed activation/return plan.
Generated management wrappers pass that pin explicitly; repeated pin arguments
are rejected, not silently overwritten. Direct immutable-directory invocation
must pass `--base BASE --control-refresh-sha256 REFRESH_PIN` itself.

## Exact return and two distinct restoration paths

The actual refreshed controller supports:

```text
--base BASE --control-refresh-sha256 REFRESH_PIN
--restart --reload --return-baseline ROOT_PIN
--return-control-refresh-sha256 REFRESH_PIN
```

This excludes activation, app-upgrade and separate-return-controller pins. Root
provenance still selects the exact original legacy manifest/plists. The current
healthy native pair remains the fresh fallback; readiness, revocation, input
stability, bounded recovery and exact-byte return checks are retained. The real
return transaction records both root and refresh pins. Independent launchd
ownership is still required for noninteractive `--yes`; a staged job is not armed.

**Before any activation**, dedicated `recover` can undo partial or committed
refresh only when original legacy bytes and the untouched original transaction
are still exact. It accepts only recognized old/new wrapper arrangements, restores
the three original *installed v1 management wrappers*, then restores the exact
schema-1 envelope last. These are not the pre-first-install wrappers in the root
receipt's older baseline.

**After activation**, `restore` instead requires an actual verified exact-return
transaction carrying both pins, exact legacy selector/plists, and real read-only
legacy dependency observations. It durably retains the return proof before any
restoration. Interrupted restore reuses that proof; it never falls back to the
preactivation allowance or synthesizes a future `verified` transaction.

```text
refresh_production_controls.py recover
  --stage FRESH_STAGE --base BASE --home HOME
  --root-sha256 ROOT_PIN --stage-sha256 PREPARATION_PIN --approve

refresh_production_controls.py restore
  --stage FRESH_STAGE --base BASE --home HOME
  --root-sha256 ROOT_PIN --stage-sha256 PREPARATION_PIN
  --refresh-sha256 REFRESH_PIN --approve
```

Artifacts and evidence remain retained after either operation. Unknown drift
refuses rather than guessing or deleting potentially used files. The transaction
schema downgrade is always the final durable edge, after all old wrappers match.
A disappeared lock at the open boundary is not recreated.

## Parent offline evidence

The corrected frozen parent replay passed **161 tests on each of Python 3.11.16
and 3.14.7**, with 835 subtests per run and no failures/errors or unexpected guard
violations. Checksummed malformed manifest/plist backups now refuse at install,
recovery and runtime admission; the new tests fail with 51 assertion failures and
zero errors per ABI against the prior code.
Seven neighboring cases requiring native APIs, subprocesses, compiler or selected
application imports were explicitly excluded. One expected denied default native
observer call per full run proves refusal under the offline guard; it is not a
successful native observation. Frozen-source hashes were unchanged before/after.

`test_control_refresh_composition.py` executes a real fixture first installation,
terminal legacy transaction, control-only stage/publication, actual installed
refreshed controller activation, real exact return, and wrapper restoration. The
native Agent fixture uses the timestamp-wrapper topology. The parent supplied
copies of the actual installed v1 source for retained old restart, recovery,
approved-job and watchdog checks. An interrupted return with native fallback
remains untouched by old recovery; corrected recovery consumes its bounded attempt.
The tests also exercise retained refreshed objects after undo and both sides of
the stable lock ordering.

`test_refresh_production_controls.py` fault-injects publication and restoration
edges, including rename success followed by fsync failure, and asserts refusal
before later mutations. The same missing-lock regression was replayed against the
prior installer implementation: **two assertion failures per ABI, zero errors**;
the corrected implementation passes. Original app/launcher/v1/root and selection
invariants are checked independently, not rebaselined after writes.

Fifty independent fresh-process probes (25 per ABI) also pass against these corrected
files. Actual fixture-installed wrappers and versioned CLIs use normal sibling
imports with native/network/application calls forbidden. Help, argument rejection,
committed/missing-commit admission, actual CLI preactivation recovery and post-undo
refusal are exercised. Parent checked both expected text and exit status. Genuine
non-launchd ownership blocks approved-job execution; forwarding past that gate and
successful native CLI restart are not claimed.

The first approved real staging attempt exposed a separate size mismatch: valid
root and activation records exceed the helper's 4 MiB cap. Staging stopped before
installed control mutation. Capacity remediation must preserve a fixed bounded
refresh limit, leave the original upgrade default unchanged, and exercise nested
receipts and actual return proof at representative size. Small fixture passes do
not establish that production provenance fits.

## Parent isolated native evidence

`verify_control_refresh_live.py` and `test_control_refresh_lab.py` keep filesystem
build/preflight separate from explicit `--live`. Eleven guarded offline tests pass
on each approved ABI. The live parent run copies the retained ServiceHost executable
without compilation, signs only the disposable lab bundle with the existing identity,
and verifies its executable-section digest stayed unchanged. Signing explicitly
selects the existing keychain while keeping the synthetic HOME: the first attempt
could not find the signer through isolated-HOME defaults and stopped before launch.
No private key is exported, and trust settings are not modified.

The successful run observed real signature/process identities for the exact
host -> timestamp wrapper -> gateway-state child chain and direct WebUI child;
then performed an independently launchd-owned restart and one induced failed-start
rollback. The controller returned `verified` for restart and `rolled_back` for the
fault. Lab selector and both plist bytes were restored exactly. Cleanup and a
separate parent readback verified all three lab jobs absent, all 15 observed PIDs
absent, no lab-port listener, and the disposable bundle signature still valid.
Production readback independently verified unchanged installed artifacts, exact
healthy legacy baseline and service PIDs, and both production one-shot jobs absent.

This closes the isolated native topology/readiness/bounded-rollback gate, not the
refresh publication gate, production restart, successful-native production return,
or capability inheritance by production tools. No second production activation has
occurred. Install-only refresh is approved; final cutover is not.
