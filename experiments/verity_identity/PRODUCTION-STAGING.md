# Native production staging (no activation)

`stage_production_native.py` prepares a **new private staging directory only**.
It does not make production cutover ready, select a release, install an app,
update a maintenance wrapper, write LaunchAgents, create an activation job, or
start/stop any service. A success receipt explicitly says `activation_ready:false`.

## Contract

Inputs are the explicit selected `production-release.json` (schema 2), completed
production identity metadata, a fresh control-version ID, and the existing
bootstrap interpreter plus explicit bootstrap TMPDIR. The bootstrap interpreter
must match both legacy job definitions. Signed bootstrap HOME is the operator's
explicit home (the current home by default), HERMES_HOME must match the common
explicit selected service value, and TMPDIR comes only from `--bootstrap-tmpdir`.
The six-key allowlist fixes PATH to the system tools and both Python switches to
`1`; caller environment and lab `<base>/home|tmp|state` defaults are not used.
The selected services and their environment-file references remain unchanged.
Metadata must declare production purpose and verified recovery; the builder does
not perform Keychain trust, vault, recovery, or provisioning operations.

The new directory contains:

- `Verity.app`, compiled from the unchanged, copied `ServiceHost.swift`, with
  identifier `com.charles.verity`, leaf-pinned designated requirement, signed
  settings and strict signature verification;
- `control-versions/<id>/` containing the launcher, restart controller, watchdog,
  approved restart runner **and `native_identity.py`**, with a byte receipt;
- `maintenance/` wrappers referencing the **future final** versioned control path;
- `candidate-release.json` referencing `~/Applications/Verity.app`, not its
  temporary stage location, and retaining the existing services dictionary
  exactly (source inventories, runtimes, argv, environment, dependencies,
  working directories, environment-file references and plist paths);
- separate `launchagents/agent.plist` and `webui.plist` proposals retaining their
  labels, lifecycle policy, logs and throttling, using `[native executable, role]`,
  `AssociatedBundleIdentifiers`, and `AbandonProcessGroup:false`;
- exact input manifest, job-definition and stable-wrapper rollback copies, Swift
  source, requirements file and stage receipt with candidate/rollback integrity.

The candidate now includes explicit per-role `launchd_overrides` for its exact
native argv, anchor, bundle association and process-group policy. Their presence
is not activation: matching controller support has passed offline migration and
exact-byte rollback tests; its live synthetic migration gate remains separate. `verify_stage()` compares entire proposed plist dictionaries with the
saved originals plus those exact overrides (and checked removal of `Program`),
so unrelated environment, logging, lifecycle or throttling drift is rejected.
All other top-level selection fields are retained exactly as well as services.

Signed settings point to the final maintenance base, final stable launcher and
its staged wrapper hash. `verify_stage()` verifies the in-stage bundle inventory,
strict leaf-pinned signature, settings/launcher hash and versioned control bytes
without installing anything at those final paths. The native controller's normal
final-path preflight is **not** claimed to pass before installation.

The builder refuses existing/symlink/noncanonical destinations, maintenance
children, the final application location, writable-by-others parents, duplicate
control versions, schema/role/bootstrap drift and revoked selections. It checks
selection/job bytes again before success. A failed build retains incomplete
artifacts without a success receipt. Use a new directory for another attempt.
This is an operator-owned staging workflow, not protection against a malicious
same-user process replacing files concurrently. Receipts are local evidence,
not an externally trusted signature over the whole deployment.

Compiler invocation uses absolute `/usr/bin/xcrun --no-cache`, a clean environment,
and an explicit `-module-cache-path`. HOME, CFFIXED_USER_HOME, TMPDIR, XDG cache,
Swift and Clang module caches all point under `stage/compiler/`. No caller compiler
flags, library paths or credentials are inherited. This contains the explicit
compiler scratch/cache outputs; it is **not an OS sandbox** or a guarantee about
macOS daemon-managed writes. Code signing also uses macOS's existing services.

The successful report remains in memory throughout final verification. Only after
verification returns does the builder write `stage-report.next.json` and atomically
rename it to `stage-report.json`. Interruption during verification cannot leave a
success-named receipt; an incomplete `.next` file is never a success signal.

## Stage-only invocation — never an installation or activation

```sh
env -u PYTHONPATH -u PYTHONSAFEPATH "$PYTHON_311_OR_NEWER" -B \
  experiments/verity_identity/stage_production_native.py \
  --root "$NEW_PRIVATE_STAGE" \
  --selected "$MAINTENANCE/production-release.json" \
  --identity "$PRODUCTION_IDENTITY_JSON" \
  --control-id "$NEW_CONTROL_ID" \
  --bootstrap-python "$EXISTING_BOOTSTRAP_PYTHON" \
  --bootstrap-tmpdir "$EXPLICIT_BOOTSTRAP_TMPDIR"
```

The CLI compiles and signs **only the new staged app**; that invocation still
requires operator authorization. The identity metadata selects the signer; lab
identity metadata is rejected. Do not run the candidate host: its settings are
intentionally wired for the final maintenance base, not a canary sandbox.
Do not feed this candidate to `prepare_cutover.py` or the schema-1 installer.

## Offline verification

```sh
env -u PYTHONPATH -u PYTHONSAFEPATH TMPDIR="$PRIVATE_SCRATCH" "$PYTHON_311_OR_NEWER" -B \
  -m unittest discover -s experiments/verity_identity -p 'test_stage_production_native.py' -v
env -u PYTHONPATH -u PYTHONSAFEPATH TMPDIR="$PRIVATE_SCRATCH" "$PYTHON_311_OR_NEWER" -B \
  -m unittest discover -s scripts/production_control -p 'test_*.py' -q
```

The staging tests use disposable metadata, source/runtime references that are
never opened, and an explicitly fake compiler/signature adapter. They cover role
separation, preserved runtime selection, no external writes, tamper/signature
refusal, revoked selections, path/symlink/version restrictions, selection drift,
and actual subprocess imports of the copied controller modules without application
imports. They are **not evidence of a production signature or native execution**.

Initial child verification: 11 new tests and 63 controller regressions passed on Python 3.14;
8 neighboring controller-lab tests passed. An initial default `python3` run used
Apple Python 3.9: the new tests passed but one existing safe-path regression failed
because that interpreter lacks the required safe-path behavior. The supported
3.14 rerun passed all 63. No application imports, launchd calls, production signing,
settings writes, or live staging invocation were performed by that verification.

Parent verification on Python 3.11 repeated all 11 staging tests and fixed the
changed-file Ruff encoding diagnostic. A new regression then reproduced three
accepted tamper cases before the fix: rollback bytes, unrelated plist environment,
and top-level candidate health URL. All 12 staging tests pass after the fix, as do
changed-file Ruff checks. Stable-wrapper rollback copies and drift checks were
added; incomplete staging remains non-activatable. Source has been committed and
pushed. The first independent review found inherited compiler scratch paths and
premature success-receipt publication. Two regressions reproduced those failures;
both pass after explicit compiler containment and post-verification publication.
All 14 staging tests pass on Python 3.11, including a real subprocess environment
boundary check. A separate real Foundation-importing Swift compile through the same
helper succeeded: 35,064-byte binary and 103 files in its stage-local module cache.
The binary was neither executed nor signed with the production identity. Evidence:
`~/.hermes/cache/scratch/verity-compiler-proof-zckj9dtg/compiler-verification.json`.
No actual production stage, final identity installation or launchd operation was
performed. Focused read-only re-review (`deleg_27605a7b`) found no remaining
blockers in the two fixes: clean compiler environment/cache paths and success
publication only after final verification. The reviewed staging source and tests
match commit `9470ba2c2ede0cdad280ee5d8649427664be4bc8`; the parent verified no
subsequent diff in those files. The reviewer did not execute tests or review the
concurrent host/controller work. Parent execution passed all 14 staging tests on
Python 3.11 and 3.14, plus 51 selected experiment/neighboring tests on Python 3.11.
This closes only the two staging-review findings, not the remaining gates below.

## Integrated environment and migration evidence

Parent verification of the returned changes passed 69 controller tests on each
of Python 3.11 and 3.14. Staging integration added two regression methods: absent
signed environment and accepted mismatched role state reproduced before the fix;
all 16 staging tests then passed. All 53 selected experiment tests passed on 3.11;
45 passed on 3.14, excluding eight signer tests requiring unavailable cryptography.

The first live environment run exposed a harness mismatch: Python/macOS adds
`LC_CTYPE` and `__CF_USER_TEXT_ENCODING` despite an explicit six-key input. A
separate direct launch of the exact interpreter with those six inputs reproduced
both extra keys while retaining every configured value. The harness now compares
those two additions against that independent baseline, rejects any other keys,
and still rejects the injected synthetic secret sentinel. It does not log values
of unknown keys. The second run correctly refused malformed settings but exposed
launchctl's `78: EX_CONFIG` output rather than plain `78`; a red/green regression
covers the narrow parser correction. Both failed receipts remain failed and
independent scans confirmed all their recorded processes/groups had disappeared.

A third fresh run, `~/.hermes/cache/scratch/verity-env-live-final3/`, passed all
**70 live cases**: legacy and explicit settings for both roles (four), and malformed
or unknown settings refused in both roles (66). The report's cleanup verification
was independently repeated: all recorded PIDs/groups gone and all jobs absent.
Only the existing lab signer and `com.charles.verity.environmentlab` were used;
no privacy APIs, production services or real application content were exercised.
The harness uses stage-local compiler scratch and converts CLI SIGTERM into a
cleanup path; uncatchable termination remains outside that guarantee. The named
exit-status regression brought the controller suite to 70 tests.

Review `deleg_4dc255cb` found one cleanup blocker: a launchctl timeout/spawn error
could abort remaining bootouts, and a ps subprocess error could skip the failure
report. It found no additional blockers in the signed-environment, legacy defaults,
Program migration, explicit reload or exact-byte rollback changes reviewed.
The cleanup now catches errors separately for each bootout and absence check,
continues every remaining target, attempts the process/group check, and publishes
a failed cleanup receipt without logging subprocess output. Process-check timeout,
nonzero exit and malformed evidence are also recorded rather than aborting report
publication. This does not guarantee cleanup after repeated asynchronous interrupts,
uncatchable process death, or a filesystem failure preventing the report write.

One new regression reproduces six red-to-green cases: bootout timeout, spawn error,
print timeout, ps timeout, ps nonzero exit, and body failure plus cleanup failure.
Each requires both role cleanup attempts, the process check and a failed receipt;
the combined failure also retains the original body error type. Parent verification
passed all **71 controller tests on both Python 3.11 and 3.14**, plus 53 selected
experiment tests on 3.11 and 45 on 3.14 (the same eight cryptography-dependent signer
tests excluded). Changed-file Ruff and diff checks passed.

A fourth fresh live run, `~/.hermes/cache/scratch/verity-env-live-cleanup4/`, passed
all 70 environment cases on the updated harness. Read-back and independent checks
again verified all recorded processes/groups gone and all jobs absent. Production
hashes, PIDs and health stayed unchanged. Focused cleanup re-review
(`deleg_a968860f`) found no remaining blockers within its requested scope: cleanup
continues after per-command failures, process-scan errors are captured, and the
failed receipt precedes raising cleanup failure. It also confirmed the regression
checks continuation and preservation of the original body error. The reviewer did
not execute tests or inspect live state. Parent verified the reviewed harness and
test files still match `ffe1280d2506e32039dc9c64a90d0a813231df0d`.
Parent integration review (`deleg_490c4598`, task 2) reported the same cleanup
finding against its older snapshot and no other blockers. That duplicate is closed
by the already-tested fix and re-review above. The synthetic migration harness now
has a six-case live pass, independently verified process/group/job cleanup and
unchanged production baseline; see `../../NATIVE-MIGRATION-CANARY.md`. Current-source
migration harness review (`deleg_4d2e07e8`) found no blockers in scope. The parent
matched both reviewed files to pushed commit
`12917ba0f24b86f9ff306b20a019fefe95338e66`. Final installation and grants are not done.

## First production-signed stage (not installed)

The parent compiled and signed a real stage at
`~/.hermes/experiments/verity-production-stage-v1` from committed source
`bf1d45dd0ef4e3f087358018ffa3b6967abc043f`, using the already-approved dedicated
production signer. It returned `staged_not_activated`, `activation_ready:false`.
Candidate SHA-256:
`18901c50d08002a54204bfbcd788ccfbbb059d859e8ecf721ac9c960f85202cc`.

A separate readback reran full stage verification and strict codesign against
production leaf `B72A53676319B035EF637A6DEF27F026009D989C`. It verified all 11
usage descriptions, exact signed settings, unchanged ServiceHost source and five
control modules, candidate/rollback inventories, and exact saved manifest/plist/
wrapper bytes against the live originals. The final app and final control version
were still absent; baseline hashes/PIDs/health remained unchanged (`health:ok`).
Neither service role was executed. Metadata source review (`deleg_0ef76b0e`,
task 1) found no blockers within scope. Parent matched its builder/tests to the
staging commit above and repeated successful stage signature/inventory verification.

The final signed settings point to real maintenance and cannot be redirected by
an isolated label/environment. Executing either production role is not a safe
pre-cutover permission test. Source audit identified a bounded alternative:
explicitly approved passive installation, followed by a temporary same-identity,
same-path candidate with signed isolated settings and fixed permission workers,
then exact final-bundle restoration. This is continuity evidence, not execution
of the real production descendant chain; those checks remain post-cutover.
The alternative is an additional restricted probe-only entry before final signing.
No such entry has been added.

Install-only and bounded permission-test approval questions were presented; no
response was received. That is not authorization. Continue isolated implementation
and review, but do not install, register, replace maintenance wrappers, request
final-identity consent, select, load/reload, or restart on the basis of staging.

## Approved install-only execution

The operator subsequently approved install-only and bounded same-identity,
same-path temporary permission testing. The reviewed installer completed; separate
read-back verified the exact installed app signature/inventory/settings, five
control modules and receipt, four wrapper bytes/modes, rollback receipt and both
candidate definitions. Source/runtime inventory validation did not import apps
or read credential contents. Selected manifest/plists and loaded legacy process
identities remain unchanged; health is `ok`. Passive registration resolves the
final app path without launching it. See `PRODUCTION-INSTALL.md`.

This supersedes the installation/approval blockers below. Permission tests have
not yet run; the native candidate remains unselected and no production restart
is authorized or performed. The original staging and failure evidence stays intact.

## Earlier remaining gates / blockers (installation superseded above)

1. **Coordinated artifact installation remains.** The source controller now
   permits only explicit native argv/anchor/association/process-group overrides,
   requires `--reload` for changes, and removes a matching legacy `Program` only
   during explicit legacy-to-native migration. Offline tests prove successful
   migration and failed-start restoration of exact old manifest/binary-plist bytes.
   The existing transaction does not install or restore host/control/wrapper
   artifacts. Their coordinated installation still needs verification; live synthetic
   definition migration now passes separately. Preserve unrelated candidates and
   retain legacy artifacts.
2. **Environment source integration reviewed; final artifacts still separate.** Optional signed
   bootstrap settings now preserve legacy lab behavior when absent and validate
   an explicit six-key environment in both Swift and the controller. The stager
   supplies this field. The 70-case synthetic live environment gate below passed;
   this is not final production-host execution or real application validation.
3. **Metadata implemented; final identity grants remain unresolved.** The unchanged
   ServiceHost has no consent APIs. The stager now seals and verifies the complete
   production Info.plist, including 11 usage descriptions; see `PRODUCTION-PRIVACY.md`
   for Apple key mapping, red/green tests and cleared source review. Production
   permission workflow, final-identity consent,
   compatible worker runtimes, rebuild/rollback continuity, and Local Network /
   Location limitations need explicit treatment and operator involvement.
4. **Final-path artifact verification remains.** A real production-signed stage
   now passes in-stage strict signature/settings/control/rollback verification as
   recorded above. This is not final-path installation or execution. Parent also
   performed separate read-only selected-source/runtime inventory validation with
   no application imports or credential-content reads. The stager itself preserves
   those inventory receipts without probing services.
5. Exercise the exact candidate control/host artifacts in an isolated synthetic
   layout, both roles and independent restarts, controller/watchdog ownership,
   failed-start bounded rollback and worker cleanup. Existing combined-canary
   evidence is necessary but not proof of this final-path migration.
6. Only after all readiness gates: obtain explicit activation permission, prepare
   and verify an independent unarmed activation job/recovery plan, then validate
   real WebUI and messaging. Logout/login and reboot require separate timing
   approval; no second real gateway may be started as a test shortcut.
