# Controls-only native refresh

Status: implemented and independently replayed **offline**; focused source review,
installed readback, and separately authorized native rehearsal remain open. This
is not a cutover-ready declaration or permission to change installed state.

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

The frozen parent replay passed **159 tests on each of Python 3.11.16 and 3.14.7**,
with 784 subtests per run and no failures/errors or unexpected guard violations.
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

These results do not establish real launchd topology, signature execution,
production restart, successful-native production return, or capabilities inherited
by production tools. No second production activation has occurred. Native rehearsal,
install-only changes and final cutover remain separately scoped approvals.
