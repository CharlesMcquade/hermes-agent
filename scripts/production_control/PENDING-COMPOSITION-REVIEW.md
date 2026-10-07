# Pending controller / management installer composition review

Development-only review of pending controller `0a85cb880dfc0bfde694dee598ad3a2e27dece6d`
composed with installer `c2d58a39b34f22383e770e5c38ca43149ae90da1` (local cherry-pick
`fab597090aa118a59f8c7a385781f11c7ae6331a`). No additional runtime defect was
reproduced in the requested practical contract; this review adds tests, not a
new release mechanism or speculative runtime changes.

## Executed evidence

`test_pending_upgrade_composition.py` installs the actual current six control
modules through `build_plan` / `apply_plan`, including real fresh-process
`control_refresh.load` admission, then imports the installed sealed Controller
and watchdog rather than combining a source watchdog with an older Controller.
The source fixture repository contains the exact six module bytes from this
checkout, committed as genuine Git objects; source lookup and installation are
not mocked. Original install history/app/signature material are fixture inputs,
not a claimed native first-install ceremony.

The starting schema-2 `rolled_back` transaction is produced by the existing
controller's interrupted-return / recovery path, not synthesized by changing a
phase string. After the management upgrade, prepare/select retain that terminal
phase, add the pending fence, and use the new refresh authority.

Five new composition cases prove:

- Plan/install/prepare/select do not request any process action. Prepare preserves
  the selector; install preserves the selector, launcher, app and plist records.
- Candidate selection with healthy old processes stays healthy and awaiting user
  restart. Both independently ordered mixed states are recognized; health and
  identity checks use running roles rather than treating selection as execution.
- Candidate verification requires stable identities and healthy snapshots across
  observations. Replacing a candidate identity or losing deep health resets the
  stability proof. The durable result is read back.
- An unknown WebUI owner blocks without restart. A real shallow liveness failure
  requests repair only after restoring the old selector, so it cannot silently
  activate the candidate.
- Explicit rollback and expiry restore only the selector. A candidate admitted
  earlier may arrive afterward; a serving candidate is never killed merely
  because the selector was restored. Even its later shallow failure cannot grant
  automatic rollback process authority.

Every composition case reads back installed wrapper/refresh receipt/journal
bytes and modes and re-admits the sealed version at cleanup. Existing tests cover
receipt/transaction/plist drift, revocation, CAS refusal, generic-controller
fencing, crash recovery, and installer failure/publication edges.

The combined stdlib suite passed **108 tests**. The six preserved launch-boundary
counterexample tests also pass: they demonstrate the deliberately absent strict
pre-exec ordering fence, not a failure of this observational contract.

Reproduction from the repository root, after creating disposable `home` and
`tmp` directories under an approved scratch location:

```sh
env -i HOME="$SCRATCH/home" TMPDIR="$SCRATCH/tmp" \
  HERMES_HOME="$SCRATCH/home/state" \
  HERMES_WEBUI_STATE_DIR="$SCRATCH/home/webui" \
  PATH=/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin \
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=scripts/production_control \
  /opt/homebrew/bin/python3 -B -m unittest \
  test_pending_user_restart test_restart_control test_transaction_recovery \
  test_control_refresh_runtime test_production_launcher \
  test_upgrade_native_controls test_upgrade_native_controls_composition \
  test_pending_upgrade_composition test_pending_restart_boundary \
  test_native_migration -v
```

The boundary tests/probe remain deliberately untracked pre-existing review
artifacts; omit `test_pending_restart_boundary` in a clean checkout without them.
No package installation, live maintenance entrypoint, release interpreter,
production write, native app launch, launchd operation or signal was used.

## Limitations and remaining installation gates

- Native signature, launchd jobs, process identities, HTTP responses and service
  restart actions are fixtures. Application preflight is injected; this does not
  prove the real candidate's inventory/startup, actual UI routes, native permission
  behavior, mixed-version application compatibility or messaging delivery.
- Process replacement is observational, not proof the user requested it. launchd
  can independently restart. Selector rollback cannot fence an already-read
  candidate or restore running processes; fallback may require user-owned restarts.
  No exactly-once or absolute availability guarantee is made.
- Installer publication is still a separate approval gate. Before it, pin the
  exact source and current installed refresh authority and verify the unchanged
  installation baseline. Install this management upgrade **before** preparing
  pending state; migrating an existing pending receipt is not covered here.
- After authorized publication, read back the final six-module sealed inventory,
  control receipt, wrapper bytes/modes/ownership, fresh refresh receipt and
  transaction fence, retained rollback bytes, plus unchanged native app/launcher,
  selector/plists and running identities/health. Fixture success is not that
  final-path evidence.
- Separately finish exact candidate readiness and the existing UI restart-path
  gate. The old WebUI still calls the old Gateway CLI until WebUI is restarted;
  the intended handoff is **Restart WebUI first, then Restart Gateway**, using the
  independently fixed native-preserving CLI. This is a user workflow requirement,
  not a new pre-exec ordering fence in the controller.
