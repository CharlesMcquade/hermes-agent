# Repeatable frozen-release preparation

This tooling is for an existing externally supervised, manifest-selected installation.
It is not a generic Hermes installer and never authorizes restarting a running service.
The installed controller/launcher remains the authority for selection and activation.

## Entry point

The one-command **preparation** gate runs controller/workflow tests, builds or
re-verifies the candidate, boots the contained canary twice, retains evidence,
and audits the current restart boundary:

```
PYTHONDONTWRITEBYTECODE=1 <nonproduction-python> -B \
  scripts/production_control/release_workflow.py --config <local-config> prepare
```

For `prepare`, include explicit `evidence_dir` (durable local reports) and `controls`
(installed controller source directory) in the config. It never selects/restarts.
Also supply `control_refresh_sha256` to run the read-only pending adapter in a
fresh process. App canary and pending admission are separate gates. Exit **0** /
`APP_SMOKE_PASSED_PENDING_GATE_CHECKED` means both checks passed, **not staged or
selected**. Missing authority or a routing failure returns exit **2** /
`APP_SMOKE_PASSED_DEPLOYMENT_BLOCKED`. Exit 1 means a preparation/test failure.
Feature-specific regression tests remain required.

Use an explicit local JSON configuration containing `baseline`, `output`, `scratch`,
`agent_repo`, `agent_commit`, `webui_repo`, and `webui_commit`. All paths must be
absolute; both commits must be exact, existing 40-character Git object IDs. `tool_path`
is optional and must not contain inherited old release/development interpreters.
Keep machine-specific configuration and evidence out of Git.

```
PYTHONDONTWRITEBYTECODE=1 <nonproduction-python> -B \
  scripts/production_control/release_workflow.py --config <local-config> build
PYTHONDONTWRITEBYTECODE=1 <nonproduction-python> -B \
  scripts/production_control/release_workflow.py --config <local-config> verify
```

`build` refuses an existing output directory. It validates the baseline before any
copy, fetches genuine self-contained Git snapshots, reconstructs an offline private
interpreter/dependency tree, preserves native-host contracts, normalizes child PATH,
runs candidate launcher preparation in a narrowly writable sandbox, writes the
fingerprint, seals the payload read-only, then inventories the final bytes. Launcher
preparation uses disposable state; it cannot certify launchers requiring a real PM
store or production configuration. It does not mutate the selected manifest or signal a service.

`verify` is read-only with respect to release/state. It validates:
- requested commit = manifest source commit = service commit = genuine Git HEAD;
- commit/tree objects exist; no external worktree/alternates dependency;
- tracked bytes and executable modes match raw Git blobs, independently of index
  assume-unchanged/skip-worktree flags; replacement refs are disabled, hooks are
  suppressed, and external Git config includes are refused;
- exact source and dependency inventories;
- both runtime identity readers, including `version_info.get_code_identity()` used
  to stamp `gateway_state.json` (not just the code-skew fingerprint);
- read-only payload modes and complete before/after inventories, including Git
  metadata, around OS-contained imports.

All interpreter probes (including baseline dependency discovery) run under the OS
sandbox, with explicit `-B` and a constructed credential-free environment. Baseline
bytes are never writable there. Probe-reported copy paths must remain inside the
private runtime. Malformed paths, symlink ancestors, overlapping source/output/state
roots and alternate Python entries in tool PATH are refused before probing. Scratch
inside application state is restricted to its dedicated `cache/scratch` subtree.

Read-only modes prevent accidental edits, not a malicious owner from using chmod.
The frozen artifact assumes no concurrent same-user mutation during preparation;
readback/inventory gates detect drift but are not a filesystem transaction lock.

A `static_verified_not_deployed` result is deliberately **not restart readiness**.

## Gate sequence

1. Implement/test/push the precise change in development checkouts.
2. Build a NEW immutable candidate from exact commits; never rsync edited files
   into a live release or fake a Git ref without its object.
3. Run the stdlib workflow regression tests and the feature/neighbor test suites.
4. Run `candidate_canary.py` on the candidate with isolated state, a constructed
   credential-free environment, OS-enforced filesystem/network containment,
   loopback-only listeners, genuine gateway-reported SHA, health/asset checks,
   a second start, exact before/after inventories, and process cleanup.
5. Audit the *currently running* user restart path and installed controller.
   Prove pending selection cannot cause watchdog-triggered activation and that
   the Gateway button preserves the installed supervisor's service definition.
6. Only a supported select-for-user-restart operation with admission, lock, CAS,
   exact rollback bytes, and unchanged live identities may publish a candidate.
7. The human operates the approved restart control. Reconcile durable journal,
   selected manifest, fresh process identities, code SHA, assets, and health after
   reconnect. Do not infer success from a returned UI response or an old receipt.
8. Perform explicitly authorized real messaging/inference checks separately.

## Hard failures

Stop on any failed gate. Do not loosen inventory exclusions, disable watchdog
protection, overwrite approved expectations from current drift, bypass signed-host
checks, mint fictitious provenance, or retry a restart without fresh evidence.

A controller with no pending-ownership protocol is not made safe by hand-writing
its selector. The reviewed pending watchdog distinguishes selected bytes from
old/new running identities. The adapter delegates to that protocol; it does not
create a second selection transaction, disable the watchdog, or alter rollback.

The generic Agent launchd restart path may regenerate a native/external service
plist. A test of process startup does not prove that the user's restart button
preserves the native host. Test the composed path against the installed definition.

## Tests

```
PYTHONDONTWRITEBYTECODE=1 <nonproduction-python> -B -m unittest discover \
  -s scripts/production_control -p 'test_release_workflow.py' -v
```

These tests intentionally reject missing `.git`, nonexistent commit objects,
worktree pointers, external alternates, stale manifest/HEAD fields, modified tracked
source, unexpected bytecode, wrong requested commits, and inherited probe credentials.
They do not prove a production cutover. No test dependency is installed into a release.

## Confidence language

Report each achieved gate and each untested boundary. No preflight guarantees a
future restart under all external conditions. `READY_FOR_USER_RESTART` must mean all
pre-restart gates passed for the exact selected bytes, not “some tests were green.”
Keep `STAGED`, `SELECTED`, `RUNNING_VERIFIED`, and `FUNCTIONALLY_VERIFIED` separate.


## Bounded user-restart adapter

Use a fresh nonproduction interpreter with `-I -B`. The adapter accepts only the
reviewed six-module refresh receipt and exact reviewed old/new manifest pins.
It prehashes the refresh receipt, bundle receipt, and **all six modules before
import**, executes retained source bytes (not pyc), then calls installed refresh
admission. A self-signed/fake bundle or caller-supplied arbitrary hash is not an
approval. Future release/refresh pins require a new review, not an override flag.

Common arguments to `select_for_user_restart.py`:

```
--base <maintenance-directory>
--controls <installed-version-directory>
--candidate <sealed-release.json>
--scratch <dedicated-disposable-scratch>
--control-refresh-sha256 <reviewed-refresh-receipt-sha256>
--expect-selected-sha256 <exact-old-manifest-sha256>
--expect-candidate-sha256 <exact-new-manifest-sha256>
```

Separate commands (append exactly one action to those common arguments):

1. `--check`: production-read-only; may write/delete disposable route fixtures.
   Does not prepare, select, observe, tick, recover, signal, or restart.
2. `--prepare --approve-prepare`: explicitly approve installed `watchdog.prepare`.
   Writes its pending receipt and transaction fence, **not** selection or processes.
   Inspect the returned receipt and retain its exact SHA-256.
3. `--select --approve-select --pending-receipt-sha256 <prepared-sha256>`:
   separately approve installed `watchdog.select`. Existing receipt, CAS, identity,
   expiry, revocation, refresh and publication guards remain authoritative.
   It publishes only the selector; no application restart is performed.

A failed write command reports `changed: null`: read the installed durable receipt,
transaction and selector before retrying. Never infer rollback from an exception.
There is no adapter rollback/recovery transaction. A post-handoff check of old
identities can fail normally; reconciliation belongs to the installed pending
protocol. Do not call `observe` as a supposedly read-only operation: it can persist
results or restore a timed-out selector.

### Current concrete blocker (v4)

The reviewed controller is installed and admitted, but candidate v4 does **not**
pin `HERMES_WEBUI_PYTHON` in its manifest environment. The launcher loads an unpinned
`runtime.env`, then restores only explicitly declared manifest variables. Candidate
`api/config.py::_discover_python` prioritizes `HERMES_WEBUI_PYTHON`, and
`api/routes.py::_run_gateway_lifecycle_command` executes that interpreter.
Therefore a clean-environment canary is not proof of the actual Gateway CLI route.
The adapter rejects v4 before stage/selection. No credential file needs to be read
to establish this gap. Do not mutate the sealed candidate: a corrected candidate
needs new inventory/manifest pins and renewed review.

The contained routing fixture imports the actual candidate WebUI/config and CLI,
checks both command constructors, then runs the real CLI dispatcher with a fake
native plist and intercepted launchctl boundary. It asserts exact print/print/
kickstart ordering and unchanged fixture plist bytes. It proves code composition,
**not a real native restart**, current production environment, message delivery, or
post-handoff identity. A synthetic interpreter override was demonstrated to change
the emitted command; an in-memory fixture with the candidate interpreter pinned
passed. Neither experiment changes the sealed manifest or authorizes v4 staging.

### Ordered human handoff, only after all gates pass

The old WebUI's Gateway button is **unsafe**: its old CLI may rewrite the native
host plist. Restart **WebUI first**, reconnect, verify the candidate WebUI's exact
native child identity, then use **Restart Gateway from the candidate WebUI in the
default profile**. Finally read durable results and verify both new identities.
Do not recommend the old Gateway button, infer readiness from app-canary success,
or promise that a future restart cannot fail. No autonomous restart is authorized.
