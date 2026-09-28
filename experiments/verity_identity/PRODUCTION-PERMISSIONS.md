# Bounded final-path permission experiment (review required)

`verify_production_permissions.py` adds **prepare**, **preflight**, **run**, and
**recover** interfaces. This is not a production cutover, restart, upgrade, or
permission grant tool. Offline tests, actual stage-only signing, copied-runtime
imports and read-only absence checks have passed. Live swap/cleanup, OS dialogs
and final-path attribution still need parent review and explicit live execution. Do not run the production app directly to test this.

## Boundaries

- Final path is `HOME/Applications/Verity.app`. Use the real operator HOME for
  parent-run preparation/live operation; a disposable HOME is for unit tests only.
- The existing original must have canonical `production_info_plist()` bytes and a
  strict signature satisfying identifier `com.charles.verity` and certificate
  leaf `B72A53676319B035EF637A6DEF27F026009D989C`.
- Copy the installed host, not a rebuilt Swift source. Re-sign only a new staged
  copy with that signer and the same explicit designated requirement. The
  original is never signed or modified. The Mach-O checker permits differences
  only inside its existing trailing embedded-signature blob: all preceding bytes,
  including load commands, must match. If codesign needs a different layout,
  preparation deliberately fails; do not weaken this check without review.
- Canonical production Info.plist is retained. Only the temporary signed
  `service-settings.json` points to the new isolated root. The frozen ServiceHost
  validates the launcher hash; the launcher embeds fixed worker settings and pins
  the unchanged copied `permissions_probe.py` and copied worker executable hashes.
- Bootstrap uses the explicitly supplied existing approved interpreter with the
  ServiceHost's isolated six-key environment. The fixed launcher spawns **one**
  newly copied, non-symlink executable at `ROOT/permission-python`, with
  `-S -s -P -u -B`, explicit `PYTHONHOME`, isolated HOME/HERMES_HOME/TMPDIR and an
  operator-selected ABI-matching bridge. No inherited PYTHONPATH, .env imports,
  application imports, maintenance imports, signing or keychain access in children.
- Worker ABI choices are 3.11 and 3.14. Bootstrap and permission-worker runtime
  are distinct. This version supports one permission name, one mode and one ABI
  per prepared root. Cross-minor checks require separate prepared roots and swaps;
  **same-temporary-host multi-ABI continuity is not implemented**. Do not claim it
  from separate successful runs. Copying a binary avoids directly executing the
  previously granted path but does not itself prove macOS has no cached grant for
  an equivalent code identity; final attribution remains an OS observation.

## Allowed observations

`--worker` is an exact allowlist: the two `Full Disk Access: Messages` / `Full Disk
Access: Safari` file tests, Accessibility, Input Monitoring, Screen Capture,
Contacts, Calendar, Reminders, Camera, Microphone, Photos, Speech, Bluetooth and
Location. Names with spaces must be quoted.

- FDA: one `os.open(O_RDONLY)` and `close` for the named fixed file; no file bytes
  are read. Only the FDA call temporarily sets HOME to the real operator HOME.
  Other work, including imports, retains isolated HOME. Two separate named runs
  cover both files; this is not a claim of blanket Full Disk Access.
- Accessibility: trust/status/optional consent and **fixed Finder AXRole only**.
  The frozen probe's broader `accessibility()` is never called. No system-wide
  focused-application lookup, window titles, text or contents.
- Other names reuse only the frozen probe's consent/status functions: no camera
  or audio recording, screen capture, contact/calendar/photo enumeration,
  Bluetooth scanning/connections, location samples, or network connection.
- AppleEvents is intentionally omitted; no new AppleEvent implementation added.

`permissions-check` never requests consent. `permissions-request` allows the
bounded consent APIs and up to 450 seconds for the permission phase. Additional
identity/exit/unload steps are independently bounded. Requesting-only records
cannot pass. `ConsentTimeout` yields `incomplete`, not success. Scalar statuses
such as denied/restricted/missing remain legitimate **completed observations**,
not authorization. A permission being allowed by macOS is not authorization to
perform a user task.

## Parent/operator phases — not commands run by the implementing child

Use a NEW root directly under the already-existing, safe, operator-owned
`HOME/.hermes/experiments`. Keep the root and all receipts for recovery. ROOT and
Applications must be on the same filesystem. BASE is the existing maintenance
base containing the already-provisioned safe `control.lock` and legacy selector.
Do not provision or repair that lock through this tool.

```text
python -B verify_production_permissions.py prepare \
  --root ROOT --base BASE --home HOME \
  --python APPROVED_BOOTSTRAP_EXECUTABLE \
  --python-home WORKER_PYTHON_HOME --abi 3.11 --bridge PYOBJC_311_DIRECTORY \
  --worker 'Camera' --mode permissions-request --approve-sign

python -B verify_production_permissions.py preflight --root ROOT

# Separate explicit bounded-live approval; not implied by signing/preflight:
python -B verify_production_permissions.py run --root ROOT --live

# Only when reconciliation is needed; never resumes forward execution:
python -B verify_production_permissions.py recover --root ROOT --live
```

`--python-home` must contain `bin/python3.11` (or `bin/python3.14` for `--abi 3.14`).
Preparation resolves that path and copies the actual executable, never a symlink.
Preparation does not execute either interpreter or import the bridge, so an ABI,
linker, or PyObjC mismatch may still fail the live handshake. Request mode is
fixed into the sealed launcher: it cannot be toggled by adding a live CLI flag.
Use a fresh prepare for a different name/mode/ABI. Actual paths must be supplied
by the operator; do not discover credentials or real Python state to guess them.

No compiler is called. `prepare --approve-sign` executes codesign only on the
staged copy, and verification on the original and temporary bundle. `preflight`
is static/signature verification, not a dry live execution. The source tree must
remain unchanged between prepare/preflight/run because launcher regeneration is
one of the preflight checks.

## Swap, identity gate and recovery

The parent holds the existing nonblocking production `control.lock` through the
swap, test, cleanup, restoration and final baseline checks. It snapshots exact
legacy selector/plist bytes, owner and mode, requires a terminal/absent activation
transaction, and calls the installer's default `no_live_native_dependency` for
admission and again before bootstrap. Restoration separately requires unchanged
selector/plists and independent absence of all artifact users; it does not require
unrelated legacy services to be running. Unknown is refusal, not permission to proceed. Coordinated controllers
cannot select native jobs while this lock is held. Advisory locks do not stop
manual launchctl actions, arbitrary same-account writers or an OS crash.

`prepare-start.json` precedes staging writes; `prepared.json` marks complete
preparation. `swap-receipt.json` is fsynced **before** the first rename and includes
both inventories, target and baseline. The original moves to `ROOT/original.app`,
then the sealed temporary moves to the exact final app path. Final-path inventory
and signature are verified before bootstrap. No production launchd target is
bootstrapped, restarted, unloaded or changed.

The single unique target is `com.charles.verity.permissiontest.<random hex>`,
with `AssociatedBundleIdentifiers=[com.charles.verity]`, `RunAtLoad=true`,
`KeepAlive=false` and `AbandonProcessGroup=false`. The target is recorded before
bootstrap so a partially successful bootstrap still enters cleanup. The parent
checks loaded-job PID and kernel PID/PPID/UID/executable/argv/start identity twice
for host, guard, bootstrap and copied permission worker, plus their process group.
Only then does it publish GO containing that worker's exact PID/PPID/PGID and fresh
nonce. A bare worker cannot replay an old GO. This is not a hostile same-UID sandbox.

Success requires completed sanitized permission records, worker/supervisor clean
exit, host service-exit status, launchd last exit code zero, target removal, and all
recorded PIDs and process groups gone. Restoration cannot proceed on unknown
cleanup. The original is restored by rename and its exact inventory/signature
rechecked; the temporary is retained as `retired.app`. No artifact is deleted or
existing destination overwritten. Baseline drift or possible live dependency
blocks restoration and retains the original rather than moving a bundle out from
under an unaccounted process.

Ordinary exceptions and a first SIGINT/SIGTERM enter cleanup. **No cleanup claim
is made for SIGKILL, OS crash, power loss or repeated interrupts.** `recover --live`
rechecks the exact receipt/baseline and cleanup before deterministic restoration.
Missing process receipts trigger an independent process census, not permanent
refusal. After exact launchd absence, cleanup checks recorded PID/PGID disappearance
and all current-user kernel executable/argv identities for the final bundle,
experiment executables and fixed isolated launcher. Census failure, malformed or
unreadable live identities refuse. A positively observed unrelated zombie has no
executable/address space and does not block this scan; recorded experiment PIDs
still require disappearance. No process arguments/environments are persisted.
Recovery cleans its exactly-owned temporary job before checking legacy baseline
drift. Drift still blocks renaming, but cannot skip experiment cleanup. Preserve
the root on unknown state; never delete the original or force a rename. Result
write failure can occur after successful restoration: earlier receipts remain,
and recovery verifies rather than trusting an absent report.

Passive LaunchServices registration is not performed: the parent reported the
installed final path already registered. This harness must not launch the real
app to register it. If that prerequisite changes, stop for separately reviewed
passive registration; no `open` fallback exists.

## Parent stage-only verification

Parent reran `test_production_permissions`, `test_install_production_native` and
`test_stage_production_native` together under disposable HOME/HERMES_HOME/TMPDIR:
**68 tests passed on each of Python 3.11 and Python 3.14** (the aggregate includes
the imported staging test class). Changed-file Ruff and diff checks passed.

Actual production-signer preparation succeeded at
`~/.hermes/experiments/verity-permission-camera-check-v1`, followed by a separate
successful `preflight`. The real codesign operation preserved every Mach-O byte
outside the embedded signature blob. The original installed app was not moved or
modified. The copied 3.11 worker loaded its standard library and all nine native
framework bridges under its explicit isolated environment; no permission API was
called. This smoke test ran under the existing Hermes ancestry, **not** the native
host, and is not attribution evidence. A read-only launchctl check confirmed the
expected `113` / `Could not find service` absence result for a new random label.

The parent independently rechecked installed production artifacts and the legacy
selector/plists/process identities; all matched, health `ok`, native candidate
unselected. Live swap/recovery and final-path permissions are still unverified;
Initial privacy/runtime review (`deleg_0aeb47ca.task-1`) found no blockers.
The lifecycle review found two recovery blockers, now covered by parent regressions:
missing pre-bootstrap receipts and reliance on live legacy-service availability.
All four exact-boundary tests failed before the fix and passed afterward; a fifth
red-to-green subcase covers a positively identified unrelated zombie. Eight added
methods cover these paths plus artifact-user refusal, unknown census, and bootout
exception reconciliation. **76 combined tests pass per Python 3.11/3.14**, including
28 permission-harness tests; Ruff/diff checks pass. The actual read-only census
now passes with no artifact users. Focused re-review remains pending. No production
service was restarted.

## Offline evidence

Run the unittest module from `experiments/verity_identity` with a disposable
HOME/HERMES_HOME and TMPDIR under the configured scratch directory:

```text
python -B -m unittest test_production_permissions -v
```

The new module passed **20 tests on Python 3.11 and 20 on Python 3.14** with
isolated scratch HOME/HERMES_HOME/TMPDIR (also 20 on the system Python 3.9).
Changed-file Ruff and repository `git diff --check` passed. Initial tests caught
nondeterministic launcher regeneration after JSON key ordering; config ordering
is now canonical before sealing/regeneration. These are offline results only.

The tests use tiny disposable app/runtime/bridge directories. All codesign calls
are fixture callbacks, launchd/kernel observation uses a fake adapter, baseline
manifests are synthetic, and subprocess.run is a tripwire. No test invokes a
permission API, executes the fake interpreter, signs, touches the keychain, reads
real maintenance state, or starts/restarts a service. Coverage includes copy,
rename-after-success, bootstrap, identity, first interrupt, cleanup, receipt and
report failures; exact original restoration; incomplete cleanup retention and
recovery; opt-ins; missing lock; default-dependency wiring; root/worker reuse;
sealed settings; completed scalar filtering and stale-GO rejection.

Limitations: these tests are not macOS signing/permission/launchd/attribution
proof. Cleanup requires independent process-census evidence and the expected
launchctl absence/exit syntax; unknown output fails closed. One worker per root, no autonomous UI,
no AppleEvents, no in-place same-host ABI switching, no grant revocation or
restoration of OS consent decisions, no broad runtime inventory seal, and no
hostile same-account filesystem defense. Original filesystem metadata is
preserved by rename; temporary copies do not promise ACL/xattr equivalence.
