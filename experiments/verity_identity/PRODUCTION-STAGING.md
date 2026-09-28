# Native production staging (no activation)

`stage_production_native.py` prepares a **new private staging directory only**.
It does not make production cutover ready, select a release, install an app,
update a maintenance wrapper, write LaunchAgents, create an activation job, or
start/stop any service. A success receipt explicitly says `activation_ready:false`.

## Contract

Inputs are the explicit selected `production-release.json` (schema 2), completed
production identity metadata, a fresh control-version ID, and the existing
bootstrap interpreter. The bootstrap must match both legacy job definitions.
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
- exact input manifest and job-definition rollback copies, Swift source,
  requirements file and stage receipt.

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

## Operator-approved future invocation — not executed against production

```sh
env -u PYTHONPATH -u PYTHONSAFEPATH "$PYTHON_311_OR_NEWER" -B \
  experiments/verity_identity/stage_production_native.py \
  --root "$NEW_PRIVATE_STAGE" \
  --selected "$MAINTENANCE/production-release.json" \
  --identity "$PRODUCTION_IDENTITY_JSON" \
  --control-id "$NEW_CONTROL_ID" \
  --bootstrap-python "$EXISTING_BOOTSTRAP_PYTHON"
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

Observed: 11 new tests and 63 controller regressions passed on Python 3.14;
8 neighboring controller-lab tests passed. An initial default `python3` run used
Apple Python 3.9: the new tests passed but one existing safe-path regression failed
because that interpreter lacks the required safe-path behavior. The supported
3.14 rerun passed all 63. No application imports, launchd calls, production signing,
settings writes, live staging invocation, commit or push were performed.

## Concrete remaining gates / blockers

1. **Initial migration cannot use the existing activation method unchanged.**
   `Controller.candidate_definitions` only permits argv, working directory and
   environment overrides; it cannot add `AssociatedBundleIdentifiers`. Staged
   full definitions are proposals, not an executable transition. A separately
   reviewed migration/rollback protocol must atomically coordinate wrappers,
   immutable versioned controls, final bundle, definitions and selected manifest.
   Preserve unrelated pending candidates and restore exact prior bytes on failure.
2. **ServiceHost's lab environment is not production-transparent.** It explicitly
   replaces HOME with `<base>/home`, TMPDIR with `<base>/tmp` and HERMES_HOME with
   `<base>/state`, ignoring the launchd environment. Selected service env restores
   some values but the current manifest has no explicit HOME/TMPDIR restoration.
   Do not create those paths or compensate silently. Resolve/retest the host or
   explicitly approved environment policy before production use.
3. **Permission metadata and final identity grants remain unresolved.** The exact
   tested ServiceHost has no consent APIs and its minimal Info.plist has no privacy
   usage descriptions. Production permission workflow, final-identity consent,
   compatible worker runtimes, rebuild/rollback continuity, and Local Network /
   Location limitations need explicit treatment and operator involvement.
4. **Actual artifact verification remains.** No real production stage was built.
   Verify strict signature, launcher/settings, immutable control receipt and final
   paths; revalidate unchanged application/runtime inventories and revocation
   policy without importing applications until separately authorized. This stage
   preserves existing inventory receipts but deliberately does not read or probe
   service source, runtime contents, credential files or live state.
5. Exercise the exact candidate control/host artifacts in an isolated synthetic
   layout, both roles and independent restarts, controller/watchdog ownership,
   failed-start bounded rollback and worker cleanup. Existing combined-canary
   evidence is necessary but not proof of this final-path migration.
6. Only after all readiness gates: obtain explicit activation permission, prepare
   and verify an independent unarmed activation job/recovery plan, then validate
   real WebUI and messaging. Logout/login and reboot require separate timing
   approval; no second real gateway may be started as a test shortcut.
