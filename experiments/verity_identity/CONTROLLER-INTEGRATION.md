# Phase 4: isolated native-parent controller integration

**Synthetic-service gate passed; review findings fixed and retested. Not deployed.**

Changing the launcher to a native parent must not make the restart controller
reject a healthy WebUI, accept an unrelated listener, or restart the gateway
when only the WebUI is unhealthy. This experiment exercises those contracts
without starting Hermes, loading messaging credentials, or altering production.

## Implementation and scope

- Imported the existing installed control baseline from source commit
  `f8bbd7689938172ea59e3a767629cd389feb342e` in a separate baseline commit.
  The stable production wrappers and versioned installation are unchanged.
- Added optional `native_host` validation to the existing controller and
  watchdog. Legacy PID-equality behavior is preserved without that field.
- Validate the bundle's inventory, strict signature and leaf-pinned requirement,
  signed settings, launcher hash, and associated launchd bundle identifier.
- Native readiness requires kernel PID/PPID/UID/executable/argv/start-time
  records, exact direct-child ownership, expected role/runtime, dynamic running
  code signature, repeated identity/job/listener checks, and the existing
  health, served assets, gateway state, freshness and stability checks.
- `ServiceHost.swift` is a separate synthetic lab host. It spawns the unmodified
  production launcher, which execs the selected synthetic Python service. A
  native guard watches a host-owned pipe and kills the owned process group on
  host death. Guard death also tears down the host's group. launchd alone
  decides when to restart; the guard never launches services.
- No new controller installation, production manifest selection, production
  launchd definition, login job, TCC request, or production process restart.

Bundle: `com.charles.verity.controllerlab`, signed with the existing approved lab
certificate. This is **not** the permission-lab identity or final `Verity.app`.
The host has no privacy usage descriptions or consent API: this phase tests
lifecycle/ownership, not permission inheritance of the new spawn/guard layout.

## Verification (2026-09-27, macOS 27.0)

Final current artifacts: `~/.hermes/experiments/verity-controller-p4/run6/`.
The reports contain locally retained PIDs/paths; raw reports are not committed.

### Seven real launchd host cases

1. Reject a direct non-launchd invocation before spawning services.
2. Native hosts own the two synthetic Python services in separate process groups.
3. WebUI host SIGTERM: old group gone, replacement ready, agent unchanged.
4. Agent Python SIGKILL: old group gone, replacement ready, WebUI unchanged.
5. WebUI host SIGKILL: guard removes old workers; agent unchanged.
6. WebUI guard SIGKILL: host removes old group; agent unchanged.
7. Agent kickstart: old group gone, replacement ready, WebUI unchanged.

Source: `host-live-verification.json`. The five restart cases include workers
that deliberately ignore SIGTERM. Initial run1 exposed surviving workers;
three recorded survivors were explicitly removed. The pipe-guard implementation
then passed. Run2 was an unsuccessful Swift build, not a test pass.

### Nine real controller cases

1. Accept exact signed native host and its Python WebUI listener (different PIDs).
2. Launchd-owned independent controller restarts both synthetic services; new
   births/PIDs, byte checks, health and runtime ownership verify.
3. Healthy native pair is not restarted by watchdog.
4. Deep-health failure reports degraded and preserves both services.
5. Repeated shallow-health failure restarts WebUI only, preserves the agent,
   removes old workers, and verifies healthy on the next tick.
6. A real unrelated loopback listener is rejected before HTTP readiness can
   stand in for ownership; the service pair stays unchanged.
7. A byte-approved but startup-failing candidate triggers bounded rollback;
   exact previous manifest/plist bytes restored and old release pair verified.
8. Changed service source bytes are refused before either service is stopped.
9. Changed native bundle settings are refused before either service is stopped.

Source: `controller-live-verification.json`. Both suites removed their launchd
jobs and checked every recorded host/child/guard/worker plus their process groups,
including short-lived crash-loop records, after unload.

### Unit and regression checks

- 63 controller unittest cases passed independently on Python 3.11.16 and 3.14.7
  (53 imported baseline cases plus 10 native-identity/adapter cases).
- 21 experiment unit/subprocess cases passed on both Python versions: 13 existing
  permission-probe cases and 8 new lab-isolation/evidence regressions.
- New/experimental Python files pass Ruff; `git diff --check` passes.
- Four whole-directory Ruff encoding diagnostics were compared against the
  imported baseline and are unchanged (one in `live_control_test.py`, three in
  `restart_production.py`). No broad baseline reformat was performed.
- Live signature preflight found `codesign -R` treats a bare string as a file:
  inline requirements need `-R '=identifier ...'`. The adapter was fixed, a
  regression added, and live validation rerun. Earlier incomplete reports are
  failures, not additional passing cases.
- A synthetic deep-health flag initially matched `deep=true`, while the actual
  controller uses `deep=1`; the fixture was fixed before counting that case.
- The production baseline reported unchanged hashes, PIDs, and healthy HTTP.

## Review reconciliation and two live failed-start controls

The review found no additional blocking host/guard issue within the stated
synthetic scope. Three harness findings were addressed:

1. Validate the resolved executable, exact app location, state/repo paths and
   actual plist dictionary before any execution, not just manifest labels.
   Unexpected labels, argv, program overrides, environment, working directory,
   redirected outputs and symlinks are rejected. Signed bundle/source preflight
   also precedes the host's bare-invocation negative control. These are lab input
   checks, not a sandbox against malicious same-user concurrent modification.
2. Keep log-based generation/group accounting independent of readiness. This
   scan was already added after the review snapshot; it now rejects empty
   evidence. Conservatively report all failed runs as cleanup `inconclusive`
   (or `not_started` if no bootstrap was attempted), never a false complete
   cleanup claim. Partially successful bootstrap attempts are also unloaded.
3. Deep-copy the initial pair into the report so later replacements cannot
   overwrite its PID evidence. The final initial pair was compared with the
   first signal cases' old generations.

`verify_harness_live.py` blocks the synthetic WebUI before it can listen, after
its worker exists. Both the host and controller harness time out nonzero,
retain a failed receipt with `cleanup_verified:false`/`inconclusive`, and unload
their jobs. Independent post-failure scans find no recorded processes/groups
remaining. These two expected-failure controls pass; the deliberately failed
runs themselves are not relabeled successful. Evidence is preserved in
`failed-start-*-live-verification.json` and `harness-live-verification.json`.
The nine controller and seven host cases then passed again on the final build.

## Reproduce (operator-approved isolated macOS lab only)

Use a fresh root; builds refuse to replace an existing artifact. Use a retained
Python 3.11+ interpreter and the previously approved lab identity metadata.
No signing credentials are printed. Do not run two verifiers on the same root.

```sh
env -u PYTHONPATH -u PYTHONSAFEPATH "$PYTHON" -B \
  experiments/verity_identity/build_controller_lab.py \
  --root "$NEW_LAB_ROOT" --identity "$LAB_IDENTITY_JSON"
env -u PYTHONPATH -u PYTHONSAFEPATH "$PYTHON" -B \
  experiments/verity_identity/verify_harness_live.py --root "$NEW_LAB_ROOT"
env -u PYTHONPATH -u PYTHONSAFEPATH "$PYTHON" -B \
  experiments/verity_identity/verify_controller_live.py --root "$NEW_LAB_ROOT"
env -u PYTHONPATH -u PYTHONSAFEPATH "$PYTHON" -B \
  experiments/verity_identity/verify_service_host_live.py --root "$NEW_LAB_ROOT"
env -u PYTHONPATH -u PYTHONSAFEPATH "$PYTHON" -B \
  -m unittest discover -s scripts/production_control -p 'test_*.py' -q
```

## Deliberate remaining boundaries

- Synthetic HTTP/state/services are explicitly fixtures, not evidence that the
  real WebUI API restart controls, gateway messaging, MCP workers, or inference
  work under this host. No second real gateway was started.
- Controller unit tests on 3.14 are not a claim of real Hermes compatibility or
  a live service-runtime swap in this phase.
- Permission continuity of the **new service host/spawn topology** still needs a
  combined isolated test; prior AppKit permission-host results cannot prove it.
- No legacy-to-native production definition migration, installed controller
  switch, final-identity grants, logout/login, or reboot has been performed.
- Group cleanup covers workers that stay in their service group. Deliberately
  detached `setsid` descendants and simultaneous uncatchable host+guard death
  are not covered. Arbitrary tool/subprocess lifetime policy needs explicit
  treatment before production use.
- The harness assumes an operator-controlled fresh lab root. It is not a
  sandbox against hostile manifests or same-user modifications. The native
  host/settings/launcher trust model is not yet a production deployment design.
- Local Network enforcement and Location remain unresolved from earlier gates.

**Next gate:** combine real application canary and
permission attribution checks with this lifecycle topology before proposing a
production cutover. Explicit cutover/restart permission is still required.
