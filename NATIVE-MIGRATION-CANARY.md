# Synthetic legacy → native migration canary

**Live synthetic canary passed; production not activated.** The parent ran the real compiler, existing lab signer, launchd and controller after the child's offline-only implementation. This remains a lab result, not final production identity or cutover evidence.

## Scope and operator approval

This builds the current `ServiceHost.swift` and copies the current native-aware production-control files into a **new private lab root**. It reuses `build_controller_lab.FIXTURE`, the stager's compiler isolation and wrappers, `Controller.restart(candidate=..., reload=True, yes=True)`, and existing host observation helpers. The controller runs as a separate launchd-owned job, not an interactive child impersonating PPID 1.

It does **not** run `stage_production_native.stage`, read production manifests, use production labels, install into Applications, change the selected production release, or sign/install `com.charles.verity`. The identity is exclusively `com.charles.verity.controllerlab`, using the existing approved `verity-lab-v3/identity.json` signer. No new signer is created. The synthetic paths/settings are not final production artifact settings and do not certify final identity permissions or a production cutover.

The operator must approve ephemeral lab signing and GUI-domain launchd activity before running:

```bash
cd /Users/charles/hermes-verity-identity-prototype
PY=/Users/charles/.hermes/releases/hermes-20260926-steer-snapshot-v3/runtime/venv/bin/python
ROOT="/Users/charles/.hermes/cache/scratch/verity-migration-$($PY -I -c 'import uuid;print(uuid.uuid4().hex)')"
env -u PYTHONPATH -u PYTHONSAFEPATH TMPDIR=/Users/charles/.hermes/cache/scratch \
  "$PY" -I -B experiments/verity_identity/verify_native_migration_live.py \
  --root "$ROOT" --live-synthetic
```

Requires macOS ARM64, Xcode command-line Swift compiler, an active GUI launchd domain, and the existing usable approved lab keychain. No automatic keychain unlock or credential prompt handling is supplied. Root must not exist, must be a direct scratch child named `verity-migration-<32 lowercase hex digits>`, and is created mode 0700. No resume/reuse of earlier roots is supported.

## Required evidence

1. Exact saved legacy plists launch both synthetic services, including an explicit `Program` equal to `ProgramArguments[0]`. Controller snapshot proves the old loopback listener and gateway ownership, health and served fixture bytes.
2. A signer-valid native candidate starts both roles but intentionally blocks the synthetic WebUI before listening. The independent controller has 12-second readiness windows and must report bounded rollback. Original legacy manifest and plist **bytes** must be restored, the old pair must be live, and all recorded failed native hosts/guards/workers and their PGIDs must be gone.
3. A successful legacy → native candidate reload must prove both roles using the controller's running signature/executable/argv/UID/birth/ownership checks. The explicit legacy `Program` must be removed by the existing controller migration logic.
4. Another independent native pair restart must verify fresh services; all prior recorded process groups must disappear.
5. Restart Agent and WebUI separately. Require a new host/child/guard/worker generation, disappearance of its old process group, and the sibling generation unchanged.
6. Finally unload only the generated lab labels; check all recorded host, child, guard and worker PIDs and PGIDs, including failed-start receipts. Legacy PPID 1 is launchd, not a fixture PID. Missing evidence is not cleanup proof. Each target's cleanup catches subprocess failures independently; process enumeration failures also fail the receipt.

`migration-success.json` is written **only after all cases and cleanup pass**. A verification failure writes `migration-failed.json`, with failed/inconclusive cleanup rather than claiming full accounting. Build/signing failures can leave an incomplete root without either receipt; that is not success. Retain the root for evidence, including exact saved bytes, captured control/Swift source, signed app, controller transaction journal and process logs. The scratch retention policy may eventually prune it; copy evidence explicitly if longer retention is needed.

## Containment and limits

- CLI accepts only a new root and explicit live opt-in; it does not accept external manifests/plists/candidates. Root/signer inputs are checked before creation. Before controller writes, exact approved synthetic manifest, fixture, environment, actual plist and captured artifact bytes are checked. Symlink escapes, production labels, conflicting `Program`, env files, import probes, foreign health URLs and service paths are rejected.
- Signed bootstrap settings explicitly name isolated HOME/TMPDIR/HERMES_HOME and the six-key bootstrap allowlist. Legacy plist environment and synthetic service environment also point into this root. The generated synthetic launcher additionally clears inherited environment before importing the captured launcher, since launchd's EnvironmentVariables augments rather than replaces its environment. Fixtures use only standard-library code, no app imports, credentials, messaging or real user state. This canary does not independently attest Python-added environment variables; that remains the environment verifier's separate gate.
- Only an ephemeral `127.0.0.1` listener is used. There is a normal bind/release/start port race; controller listener ownership fails closed rather than accepting another process.
- Private-root checks and in-memory byte approvals detect observed drift, but are not an OS sandbox against a malicious same-UID process racing file replacement. Compiler caches are root-local; macOS signing/launchd may update daemon state outside the root.
- PID reuse or unavailable process/signature inspection conservatively blocks success. Hard-killing the verifier or losing the host can prevent `finally`; no unconditional cleanup claim is made. Do not delete evidence or kill unrelated processes to force green results.
- The synthetic legacy supervisor explicitly kills and reaps its own TERM-ignoring worker on termination. Native fixtures retain TERM-ignoring workers and depend on the native host/guard for cleanup. This does **not** establish cleanup of arbitrary production legacy descendants; inventory and quiesce those at cutover.
- CLI SIGTERM enters cleanup; repeated asynchronous interrupts, uncatchable process death and storage failures remain outside the guarantee. Independent-controller targets are registered with outer cleanup before bootstrap, so partial start/unload errors do not lose the target.
- Offline tests are not live migration proof. Final-path artifact preflight, production signer recovery, permission grants, real-runtime compatibility and explicit production activation approval remain separate gates.

## Parent live evidence

Fresh run `~/.hermes/cache/scratch/verity-migration-b8f1a754d8884b37999265fc6b4caa9a/migration-success.json`
passed all six named cases and final cleanup. Independent readback verified all
three generated labels absent and every recorded PID/process group gone. Production
baseline hashes, PIDs and health were unchanged (`health:ok`). Both native role
signatures/ownership, failed-start exact-byte legacy rollback, whole-pair restart
and each-role sibling-preserving restart were exercised, not mocked.

Earlier roots remain failed/inconclusive. The first run attempted a snapshot before
listeners were ready; the parent reused the controller's bounded `wait_ready()`.
The second reached successful exact-byte rollback but detected four surviving
legacy TERM-ignoring test workers. The parent matched each worker's kernel birth,
UID, executable, exact fixed argv and recorded group before removing it, then
verified all recorded PIDs/groups gone. The fixture was changed to give only the
legacy supervisor explicit child cleanup; no native-host cleanup assertion was
removed. Those earlier failure receipts were not relabeled as passes.

Ten offline methods now cover the independent controller cleanup owner and
per-command faults in addition to the initial nine. Parent regression runs passed
63 experiment and 71 controller tests on Python 3.11; Python 3.14 passed 55
experiment and 71 controller tests (eight cryptography-dependent signer tests
excluded). Changed-file Ruff and Git diff checks passed. Focused current-source
review (`deleg_4d2e07e8`) found no blockers within its stated scope: synthetic input
containment, exact rollback, native process/group accounting, cleanup continuation
and post-cleanup success publication. It confirmed the readiness/controller-cleanup
concerns were historical, not findings against the current source. This was a
read-only source review, not an independent rerun of the live or offline tests.
The parent matched both reviewed files to pushed commit
`12917ba0f24b86f9ff306b20a019fefe95338e66`; final production gates remain separate.

## Offline verification

```bash
env -u PYTHONPATH -u PYTHONSAFEPATH TMPDIR=/Users/charles/.hermes/cache/scratch \
  /Users/charles/.hermes/releases/hermes-20260926-steer-snapshot-v3/runtime/venv/bin/python \
  -B -m unittest discover -s experiments/verity_identity -p test_native_migration_live.py -v
```

The tests use disposable local directories, a fake compiler/signing runner, and injected launchd/process observations. They cover refusal before writes, exact actual-plist boundaries, matching Program removal using real controller logic, missing/surviving process-group evidence, failure-only receipts and cleanup subprocess exceptions. They must never be represented as live signature or launchd results.
