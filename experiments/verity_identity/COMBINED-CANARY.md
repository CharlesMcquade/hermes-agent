# Phase 5: real WebUI and service-topology permissions

**In progress: service-role checks and real WebUI lifecycle pass; permission
operations from an actual WebUI-launched child remain to be tested. Not deployed.**

The preceding phase used synthetic services. This phase reuses the selected
frozen WebUI source read-only, with the already-tested `ServiceHost.swift`, the
previously granted signing-lab identity, and exact lab-bundle restoration.
No production controller, manifest, app, job or permission is changed.

## Current verified results

Local artifacts: `~/.hermes/experiments/verity-combined-p5/run1/`.
Actual selected source: `hermes-20260926-quiet-delegation-v1` (the current live
selector, not the older release mentioned in the initial architecture snapshot).

- Six check-only permission cases passed: agent and webui roles on Python 3.11
  and 3.14, bare 3.14 negative control, then hosted 3.14 restoration. All previously
  expected 14 categories/operations match, including protected read-only file
  opens and Finder AX role. Location/focused-app AX remain limitations.
- Five real WebUI lifecycle cases passed: cold start with five served-asset
  hashes, host SIGTERM, Python child SIGKILL, host SIGKILL, and the real
  `/api/webui/restart` request followed by replacement-host readiness.
- Real WebUI runs on the previously ungranted copied Python 3.11 executable,
  loading the selected frozen source and selected 3.11 site-packages. This is
  not a Python 3.14 application-compatibility claim.
- 27 experiment unit/subprocess tests pass on both Python 3.11 and 3.14,
  including six new result-checker and exact-restoration tests.
- Original signing-lab bundle inventory restored exactly after each invocation;
  recorded processes/groups gone and production selector/PIDs/hashes/health unchanged.

The first real-app attempt stopped before readiness because absence of an lsof
listener raised ControlError instead of remaining a pending-start observation.
The runner now waits for that transient state; the complete subsequent lifecycle
suite passed. This was a harness readiness issue, not an observed app startup crash.

## Isolation and limits

- The service-host candidate is staged under the phase-5 root. During a live
  test, the existing signing-lab bundle is renamed aside and the candidate is
  placed at the same lab path. `finally` restores the exact prior inventory,
  even on test failure. The original host source is unchanged; no new consent
  or permanent installation is performed.
- Only the WebUI is a real application. The `agent` role can run only the
  check-only permission probe; no second messaging gateway is started.
- The WebUI gets disposable HOME, Hermes home/base/config/state, loopback-only
  listening, empty credential-file inputs, auto-install off, and the existing
  test-network guard. The guard blocks public connections in its Python process
  but is not an OS sandbox: it permits private/local networks and does not
  constrain arbitrary subprocesses. No chat/inference/model requests are sent.
- Permission probes alone get the real HOME so the two fixed protected file
  opens hit the intended targets. They never read those file contents or start
  the real application with the real HOME. No camera/microphone/screen recording,
  contact/photo enumeration, network scanning, or location sampling occurs.
- Role permission checks and WebUI lifecycle checks are not yet proof that
  a child launched *by the real WebUI* retains the same permissions. That final
  combined descendant-chain test is pending the terminal-API isolation review.
- The current real WebUI restart endpoint does not have the newer preflight
  admission feature. Its successful self-restart does not prove that unsupported
  API preflight contract. The separate controller's refusal tests remain phase 4.
- Detached descendants, final-identity signing recovery, Local Network enforcement,
  Location, production migration, logout/login, and reboot remain outside this result.

## Reproduce the completed portions

Use a fresh root for building and the existing approved lab identity. Never run
concurrent tests or use a production app as the lab. The runner refuses active
lab jobs and validates signed bundle inventories before replacement.

```sh
"$PYTHON" -B experiments/verity_identity/build_combined_lab.py \
  --root "$NEW_ROOT" --lab "$GRANTED_SIGNING_LAB" \
  --identity "$LAB_IDENTITY_JSON" --selected "$READ_ONLY_SELECTED_MANIFEST"
"$PYTHON" -B experiments/verity_identity/verify_combined_permissions.py --root "$NEW_ROOT"
"$PYTHON" -B experiments/verity_identity/verify_combined_webui.py --root "$NEW_ROOT"
```

Strip inherited `PYTHONPATH`/`PYTHONSAFEPATH` when invoking these from Hermes;
use a retained 3.11+ interpreter. No signing private keys or credential files
are copied into the candidate or committed to source.
