# Native one-hop maintenance: refused boundary

**Decision: do not implement a maintenance bypass for the current v1.**
`install_production_native.py` retains its original upgrade admission/census and
4 MiB default readers; only an explicit refresh-only capacity parameter was added.
No `maintenance_native.py` is
provided: an adapter that returns permission without a production exclusion
mechanism would conceal the missing prerequisite. The existing default remains
fail-closed, including unreadable PID identities. This artifact is not live-go
approval, a repair to the prior readiness failure, or authorization to stop jobs.

**Scope clarification:** this refusal concerns replacing the app pathname.
The separate [controls-only refresh](CONTROL-REFRESH.md) keeps the app and stable
launcher unchanged and uses the old transaction-schema rejection as a management
fence. It has independent offline implementation/evidence; it does not supply or
bypass the launch-exclusion mechanism specified below. Source review and live
readiness for that route remain separate gates.

## Exact missing mechanism

The missing mechanism is an enforceable, crash-persistent **closed launch
admission boundary covering every old consumer**, plus proof that all previously
admitted consumers have drained. Neither the installed v1 nor the permitted
installer-only edits can establish it:

- `stage_production_native.wrappers` imports versioned Python before entering
  controller code. A process which imported v1 can retain its entry points
  indefinitely; changing the wrapper does not invalidate its objects.
- `restart_production.control_lock` holds an advisory flock on an opened inode.
  It excludes another participating operation while held, not imports, direct
  launcher execution, or future calls through retained v1 objects. Releasing it
  after a failed/partial cutover reopens those operations. Replacing the lock
  pathname would create two independent locks; it is not a repair.
- `production_launcher.main` reads the selected manifest, validates, and execs
  without this lock. A selected legacy manifest does not close its admission.
- `ServiceHost.swift` reads settings and the stable launcher before spawning its
  group guard through the original executable path (`CommandLine.arguments[0]`).
  No maintenance gate precedes those reads/spawns. Startup concurrent with either
  app rename cannot be made safe by adding checks only to the installer.
- Repeated process census is an observation, not a reservation of the next
  instant. Protected-process EPERM does not become absence evidence under a
  same-user policy. Opaque independent interpreters cannot be declared unrelated
  by UID, name, argv alone, or a statement that the operator owns the session.

Cooperative means independent old processes obey **their existing protocol**,
not that they retroactively obey a newly written maintenance boolean. This
boundary includes automatic restart/watchdog triggers and independent old
controllers; it excludes hostile same-UID writers and hostile root. There is
currently no complete registered set of those independent consumers or an old
consumer drain/revocation handshake. Stopping a guessed list of Python processes,
assuming no manual launcher invocation, or trusting a supplied `True` changes
that boundary rather than implementing it.

## What exact launchd exclusion would and would not establish

Documentation inspected offline: Command Line Tools SDK
`usr/share/man/man1/launchctl.1`, SUBCOMMANDS `bootstrap | bootout`,
`enable | disable`, and `kickstart` (lines 90–124 in the inspected copy).

- `disable service-target` prevents that service from being loaded in that domain
  until enabled, and persists across boots. It is not documented as terminating
  an already running service.
- `bootout service-target` removes that service definition. A bare domain target
  can remove a domain, so it must never be substituted for an exact service.
- `kickstart` requests immediate execution regardless of launch conditions.
- The inspected manpage does **not** document `bootout --wait`. The controller's
  use of it is source evidence, not sufficient documentation of exit/drain
  guarantees for a new maintenance protocol. No launchctl command was executed.

Thus exact disable followed by exact bootout, covering selected **and every
launch-capable maintenance job**, would be a necessary component of a future
protocol, not sufficient quiescence evidence. It does not disable a Python
object, a direct exec, another service label/domain, or a surviving descendant.
Neither successful command status nor service absence proves those are gone.
The current dependency checker also requires the selected jobs to be loaded;
a bootout implementation cannot reuse that check as affirmative proof.

## Minimum contract required before reconsidering implementation

This is a prerequisite specification, not an implemented state machine:

1. Pin one user, one base, one original receipt, both stages, exact service
   targets/definitions, and a **complete independently verifiable launch-owner
   set**. Unknown relevant identities or unexpected descendants refuse. The set
   must cover independent consumers, not just selected launchd parentage.
2. Close admission for that set before draining. A future participating host
   must acquire the same stable lock/generation before settings, imports and
   spawning. Previously imported v1 consumers require verified termination or
   an already-supported revocation/drain handshake; editing new code cannot
   supply that handshake to them. No arbitrary process killing is permitted.
3. Pin lock device/inode, owner and mode; never replace it. Observe exact job
   definitions and disabled states before changing them, durably record intent,
   disable/bootout exact targets, and verify both job exclusion and termination
   of every relevant identity/descendant. Unknown means stop, not omit.
4. Hold exclusion through copies, both publication renames, wrapper publication,
   verification, commit, and all recovery renames. Detect identity, baseline and
   owner-set drift after each journal write before the next mutation. Preserve
   the original app inode/content/modes, original controls/root receipt, and
   selector/plist bytes/modes exactly as the existing one-hop contract requires.
5. A crash must leave admission closed independently of process-owned flock.
   Recovery reacquires the same authority and reconciles observed artifacts and
   exact job state, never merely a journal phase. Partial recovery retains
   exclusion and refuses uncertain state. Cleanup restores only proven original
   job enabled/loaded states after full pair verification; it must not blindly
   enable every job or reopen admission in `finally`. Service-manager state
   restoration and readback need separately reviewed production semantics.

Satisfying points 1–2 for immutable current v1 needs an additional, separately
approved bootstrap exclusion/consumer-retirement mechanism. A new cooperative
protocol in future consumers alone does not bridge this one-hop transition.
GUI logout, reboot, root daemons, permission changes, watchdog suppression, and
installed-script rewrites are not authorized substitutes. No small mechanism
within the permitted files and current consumer protocol was established.

## Offline evidence and limits

`test_maintenance_native.py` imports the real controller and launcher only after
subprocess/native/network/exec tripwires are installed. Its two tests use isolated
HOME/HERMES_HOME/state/TMPDIR, stdlib unittest (not repository discovery), real
flock and disposable files. They demonstrate:

- An entry point imported before locking is blocked by flock while held but
  remains callable after wrapper replacement and lock release. Native controller
  observations are stubbed; this is retained-code evidence, not a live restart.
- The real launcher reaches an intercepted exec attempt while the same unchanged
  lock is held before retention, in the missing-app gap, and after publication.
  Manifest/inventory validation is real for a tiny credential-free fixture.
  No child executes; no application module imports.

The child's direct replay passed both tests on Python 3.14. Its attempted
Homebrew Python 3.11 path was absent, despite the supplied retained interpreter
being available. The parent independently replayed both tests on the actual
Python 3.11.16 and 3.14.7 interpreters as part of a frozen 131-test aggregate:
zero failures/errors and no external-operation guard violations on either ABI.

These tests establish only the two counterexamples above. The controller test
reaches its read-only entrypoint after lock release; it does not execute an old
restart or prove that one is running in production. The launcher test intercepts
exec on a legacy fixture; it does not execute a native host across the rename.
Tests of native startup, launchd exclusion, unexpected descendants, post-journal
drift and partial recovery of a new maintenance path are **not claimed**: there
is no such path. Swift startup is source evidence only. Existing upgrade fault
fixtures are not rebranded as maintenance proof. No signing, compilation, native
process reads, launchctl, network, installed artifacts, credentials or activation
was used. Source/documentation commits are separate from these offline checks.
