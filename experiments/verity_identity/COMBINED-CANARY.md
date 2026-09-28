# Phase 5: real WebUI and service-topology permissions

**Live checks pass; final focused harness review pending. Not deployed.**

The preceding phase used synthetic services. This phase reuses the selected
frozen WebUI source read-only, with the already-tested `ServiceHost.swift`, the
previously granted signing-lab identity, and exact lab-bundle restoration.
No production controller, manifest, app, job or permission is changed.

## Verified results

Local artifacts: `~/.hermes/experiments/verity-combined-p5/`.
Actual selected source: `hermes-20260926-quiet-delegation-v1` (not the runtime
release `hermes-20260926-steer-snapshot-v3`).

| Evidence | Result | Receipt |
|---|---|---|
| Service-role check-only permissions | 6 cases pass | `run1/service-permissions-verification.json` |
| Real WebUI lifecycle | 5 cases pass, repeated with OS network restriction | `run2/real-webui-verification.json` |
| Real WebUI terminal descendant permissions | 5 A/B/A cases pass | `run2/terminal-chain-verification.json` |
| Experiment unit/subprocess suite | 29 tests pass on both Python 3.11 and 3.14 | `python -B -m unittest discover -s experiments/verity_identity -p 'test_*.py'` |

The six role cases cover agent/webui roles on Python 3.11 and 3.14, a bare 3.14
negative control, and hosted 3.14 restoration. Fourteen expected category/operation
results match; Location and focused-app AX remain limitations.

The five lifecycle cases cover cold start with five served-asset hashes, host
SIGTERM, Python child SIGKILL, host SIGKILL, and real `/api/webui/restart` followed
by replacement-host readiness. Source, executable, exact argv, listener ownership,
parent-child relationship, signature and process birth identity are checked.

The terminal chain is the real frozen WebUI on copied Python 3.11 → `/bin/sh -i`
PTY → bounded copied-Python helper → fixed permission workers. The five cases are:

1. Hosted WebUI, Python 3.11 worker.
2. Hosted WebUI, Python 3.14 worker.
3. Bare WebUI, same Python 3.11 worker.
4. Bare WebUI, same Python 3.14 worker.
5. Hosted WebUI again, same Python 3.14 worker.

Both protected files (`Messages/chat.db`, `Safari/History.db`) open read-only
under Verity, fail under bare Python, and open again after restoration. No bytes
are read. AX authorization and Finder's AX role likewise pass → fail → pass.
Focused-app AX still returns `-25204`; the successful Finder operation does not
establish that broader operation. No new permission requests are made.

An explicit handshake holds the helper while the harness verifies the live
WebUI/shell/helper kernel identities. The shell's separate session/process group
is tracked, closed through the real API, and checked for surviving processes.
Original signing-lab inventory is restored exactly after each invocation;
recorded processes/groups are gone and production selector/PIDs/hashes/health
remain unchanged.

## Isolation, source review and limits

- Only the WebUI is a real application. The `agent` role runs a check-only
  permission probe, never another messaging gateway. No chat/inference request
  or model-catalog request is made. No messaging delivery is tested.
- The existing signed lab bundle is temporarily renamed aside and the staged
  service-host candidate placed at the same lab path. `finally` restores the
  original inventory even if the gate fails. No new signer, permanent app
  installation or production launchd write is involved.
- The frozen `server.py` runs directly, bypassing bootstrap's dotenv/installer
  behavior. Disposable HOME, Hermes home/base/config/state, empty session and
  plugin state, explicit import paths, loopback bind, auto-install off and
  `HERMES_SKIP_CHMOD=1` keep production state out of the canary. Frozen source
  `.env` absence is checked without reading credentials.
- The final terminal/lifecycle runs additionally use a per-process
  `/usr/bin/sandbox-exec` policy: deny outbound networking except localhost and
  deny writes to the selected WebUI/agent/runtime directories. It changes no
  global firewall. The direct copied-Python helper uses unpatched `connect_ex`
  against a documentation-range address; all five terminal cases receive
  EPERM/EACCES, not timeout or connection refusal. This verifies an inherited
  OS denial, distinct from the WebUI's Python-only network guard.
- This is not a whole-machine zero-egress claim or proof concerning networking
  delegated to unrelated system daemons. The older `run1` checks had only the
  WebUI Python guard, which allows private/local networks, omits some socket
  paths and does not survive exec. Do not describe it as a complete sandbox.
- The PTY uses `/bin/sh -i`, with isolated HOME and no personal shell startup
  files. Terminal environment allowlisting drops PYTHONHOME and Hermes variables;
  the fixed command supplies the exact runtime and a minimal environment.
  Only the two FDA workers receive the real HOME, not WebUI, shell, wrapper or
  Accessibility worker.
- The terminal worker set is deliberately restricted: two FDA descriptor
  open/close operations and Accessibility status/handle/role operations.
  No app text/titles, images, contacts, events, photos, location, keys or media
  are collected. Workers have deadlines and no consent-request mode.
- Real WebUI uses copied Python **3.11** with the selected 3.11 dependencies.
  Python 3.14 **descendant workers** pass. This does not establish that the entire
  WebUI and its dependency set run on Python 3.14.
- The current restart endpoint acknowledges then SIGINTs itself; launchd/native
  supervision supplies the restart. It has no newer restart-preflight admission
  feature. Separate controller refusal tests remain phase 4.
- Clean explicit terminal closure is proven. An active detached PTY surviving
  hard WebUI/native-host death is not covered by the native guard's process-group
  guarantee. Neither intentionally escaped descendants nor simultaneous
  host-and-guard SIGKILL are covered.
- Production identity/signing recovery, Local Network privacy enforcement,
  Location, production migration, messaging, logout/login and reboot remain
  separate decisions/gates. Passing this lab does not authorize cutover.

The initial real-app attempt stopped before readiness because absent lsof
listeners raised ControlError rather than remaining pending. The harness was
corrected and subsequent complete lifecycle runs passed; this was not an
observed application startup crash.

## Terminal HTTP contract

Create an empty session with `POST /api/session/new`, explicit isolated workspace
and `worktree:false`. Start using `POST /api/terminal/start` with session ID,
rows/cols and `restart:false`. Attach the persistent SSE endpoint
`GET /api/terminal/output?session_id=...` before sending fixed shell input to
`POST /api/terminal/input`. This is not an exec-and-JSON-poll API. Reassemble
`output` chunks before parsing bounded JSON and the shell exit-status sentinel.
Input acknowledgment and shell closure alone do not establish probe success.
Close using `POST /api/terminal/close`, then verify known PIDs and groups are gone.

## Reproduce

Use a fresh root and the existing approved lab signer. Never run concurrently
or substitute a production app for the signing lab. Strip inherited PYTHONPATH
and PYTHONSAFEPATH; use a retained 3.11+ interpreter and scratch TMPDIR.

```sh
"$PYTHON" -B experiments/verity_identity/build_combined_lab.py \
  --root "$NEW_ROOT" --lab "$GRANTED_SIGNING_LAB" \
  --identity "$LAB_IDENTITY_JSON" --selected "$READ_ONLY_SELECTED_MANIFEST"
"$PYTHON" -B experiments/verity_identity/verify_combined_permissions.py --root "$NEW_ROOT"
"$PYTHON" -B experiments/verity_identity/verify_combined_webui.py --root "$NEW_ROOT"
"$PYTHON" -B experiments/verity_identity/verify_terminal_chain.py --root "$NEW_ROOT"
```

No signing private keys or credential files are copied or committed.
