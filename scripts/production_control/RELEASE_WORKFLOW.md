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
On the currently unsupported pending-activation boundary it returns exit **2**,
`APP_SMOKE_PASSED_DEPLOYMENT_BLOCKED`, with a machine-readable report. This is an
intentional safety refusal, not an invitation to bypass the gate. Exit 1 means a
preparation/test failure. Feature-specific regression tests remain required.

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

A controller with no select-only operation is not made safe by hand-writing its
selector. In the current native-host contract, the watchdog compares the running
WebUI child's exact executable/argv with the selected manifest. Selecting a new
path can therefore cause an automatic restart even while the old listener is
healthy. A terminal activation transaction alone does not prevent this.

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
