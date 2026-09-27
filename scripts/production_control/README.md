# Resilient local Hermes production control

## User story and proven failure

A healthy WebUI must not be stopped only to discover its replacement is forbidden
because someone committed an unrelated edit in an Agent checkout. Restart is not
deployment, and moving development HEAD must not change production launchability.

The September 21 incident was reproduced with the **actual legacy validator**:
old approval + current checkout refused Agent and WebUI; changing only the Agent
commit in the manifest made both pass. The failure occurred before application
execution, not in the title-policy code.

Local incident evidence (America/Chicago):

- 23:37:31: Agent HEAD advanced from `afbe045531afd28fb61c702eee10561ecbf56302`
  to `0a70319b64d017b7ad7b7d31bdc7d12f867705b4` (one title-tag insertion).
- 23:40:27: WebUI accepted `/api/webui/restart`, then interrupted the healthy PID.
- 37 startup refusals followed: `agent: HEAD differs from approved release`.
- 23:44:34: watchdog retried the same deterministically blocked launch path.
- 23:46:48: external repair advanced the Agent pin in the manifest.
- 23:47:04: replacement started; 23:47:09 first observed successful request.
- Separate HTTP bug: unread `{}` restart body contaminated the next keepalive
  request into `{}POST`, returning 501. Regression reproduced before patch.

Counterfactual: preflight before SIGINT would have rejected the restart while
preserving the healthy WebUI. Frozen releases also remove mutable checkout HEAD
from routine startup authorization entirely.

The running gateway still reported `afbe0455` after the repair; editing a manifest
did not update its process. The preserved fallback uses that observed running
version, not the repaired checkout's HEAD. WebUI source: `9f51c03e`.

## Authority and design

- `production-release.json` schema 2 selects an explicit Agent/WebUI pair.
- Sources, private Python distribution, and installed packages are copied into
  separate versioned release directories. Startup verifies inventories offline.
- `.git` metadata is not launch authority. Unexpected source files, import
  shadows, bytecode, dependency changes, or escaping symlinks fail preflight.
- Source `.env` is not bundled. Credentials/state remain under Hermes home.
- Python safe-path mode excludes the writable state cwd from module discovery;
  approved source directories are explicit. User site-packages are disabled.
- No network install, Git fetch, branch reset, moving tag, or auto-blessing during
  startup. Release paths are retained and are not an auto-update channel.
- launchd remains sole supervisor. CLI manager markers prevent generic install
  and refresh from replacing managed definitions. WebUI restart checks local
  manager metadata before acknowledgement or SIGINT.
- One flock serializes watchdog/restart. Preflight occurs before interruption.
- Candidate activation first proves the old live pair healthy. Old manifest and
  exact plist bytes are saved durably before candidate publication. A fresh
  watchdog/controller reconciles an interrupted transaction.
- A rollback consumes one durable attempt before acting; failed/interrupted
  rollback is terminal, not an infinite loop. No known-good approval expiry.
- Informational journal I/O failure cannot prevent rollback. Transaction backup
  persistence remains mandatory before destructive actions.
- `revoked-releases.json` may revoke release IDs or service-content digests;
  malformed policy fails closed. Revocation is checked on launch and recovery.
- Shallow process/HTTP failure drives bounded watchdog restarts. Deep dependency
  failures report degraded without blindly killing a serving WebUI. New-PID
  grace and persisted cooldown/backoff prevent restart storms.

## Tools

All scripts here are standard-library control-plane programs. Application imports
are checked using the selected release interpreter with temporary isolated state.

- `release_build.py`: offline preparation only. Pass exact source refs, source
  venv executable, state dir, environment path, output dir, verification note.
  Do not resolve a venv interpreter symlink before querying its site-packages.
- `canary.py MANIFEST --output RECEIPT --test-api`: actual frozen WebUI under
  disposable launchd label/HOME/loopback port, no production credentials or
  messaging adapters. Cold start, SIGTERM, SIGKILL, API refusal-preserves-PID,
  accepted API restart, deep health, five static-file hashes, cleanup.
- `live_control_test.py RECEIPT`: real launchd, explicitly synthetic services;
  routine restart, bad candidate rollback, tamper refusal before interruption.
- `install_controls.py`: one-time schema-1 to schema-2 migration. Versioned control
  bundle, dual-schema bridge, atomic pointer publication. Does not stop or start
  services. An interrupted installation retains a compatible launcher.
- `prepare_cutover.py`: stages explicit one-shot launchd cutover; never loads it.
  Candidate may replace cached launchd Python/cwd/env via explicit `--reload`.
  Preserve the old definitions until verification so rollback remains exact.

## Local operating runbook

Installed base: `~/.hermes/maintenance`. Read-only check:

```sh
python3 -B ~/.hermes/maintenance/restart_production.py
```

Interactive routine restart (both services; intentionally disruptive):

```sh
python3 -B ~/.hermes/maintenance/restart_production.py --restart
# Type: restart
```

Prefer a preserved release interpreter rather than Homebrew's moving executable.
Never invoke `--yes` as a child of the service being restarted: it requires PID 1
as parent. An explicitly authorized independent launchd job is the automation
path. Do not bootstrap/kickstart a staged cutover without the user's approval.
`RunAtLoad=false` and `KeepAlive=false` keep it one-shot and unarmed when staged.

Candidate promotion is `--restart --activate /absolute/candidate.json`; add
`--reload` only for explicit launchd-definition migration. A normal kickstart
uses cached definitions and **does not reread an edited plist**.

Read back after cutover:

1. `restart-result.json` has matching operation ID and `verified` status.
2. Both launchd PIDs changed; WebUI listener is its launchd PID.
3. Gateway child belongs to its launchd wrapper and reports expected code SHA.
4. Shallow/deep JSON health pass, server timestamp is fresh, five served hashes
   match the selected snapshot.
5. Persisted and loaded argv/cwd match. `activation-transaction.json` is terminal.
6. Verify actual messaging separately; health is **not** end-to-end delivery proof.

`rolled_back` means candidate failed but prior pair passed recovery checks.
`rollback_failed` or corrupt transaction means stop automatic attempts, diagnose
logs, inspect actual PIDs/state, and explicitly reconcile. Do not delete the
transaction merely to bypass refusal. A whole-disk I/O outage cannot be repaired
by a source rollback; repair storage first. Never reset dirty checkouts.

Keep the selected snapshot, prior known-good snapshot, and control interpreter
snapshot. Never prune a runtime still referenced by loaded plists, manager
preflight, watchdog wrappers, manifest, or transaction backup. Do not update
source or packages in-place inside a release directory.

## Verification and limits

Focused lifecycle suites and hermetic fault tests are required before install.
Fault coverage includes cutover writes/kickstarts interrupted with BaseException,
concurrent locks, corrupt manifest/transaction/policy, revoked fallback, failed
rollback with no retry loop, journal I/O failure, request framing, dependency
preflight, import shadowing, and exact installed-file hash read-back.

Canaries prove real process recovery, not a full host reboot or messaging delivery.
This is still one Mac, one disk, one user launchd domain. Hardware loss, macOS
failure, unavailable network/model providers, incompatible state migrations, and
credential expiry are not solved by restart control. Automatic source rollback
must not be used for an incompatible state migration without a state backup and
an explicit migration/recovery plan. No responsible operator can promise this
single-host deployment will never fail.
