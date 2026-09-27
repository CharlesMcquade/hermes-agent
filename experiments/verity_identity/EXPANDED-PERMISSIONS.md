# Phase 3: expanded macOS permission continuity

**2026-09-27 — isolated lab only. No production migration/restart.**

## Result

Seven check-only continuity cases passed using two independently compiled,
certificate-signed native hosts and Python 3.11.16 / 3.14.7:
initial host, rebuilt host, Python minor swap, exact same Python bare from
launchd, restoration under the host, and rollback on both Python slots.

The hosted cases passed:
- **Full Disk Access:** read-only descriptor open/close on each of Messages and
  Safari databases. The final probe does not read database bytes.
- **Accessibility:** authorized plus a real read of Finder's AX role (value discarded).
- **Input Monitoring / Screen Capture:** authorized preflight only, no collection.
- **Camera, Microphone, Contacts, Calendar, Reminders, Photos, Speech, Bluetooth:**
  authorized/full native status. No media, records, scans, or connections requested
  by these permission probes.

The bare Python 3.14 negative control lost every required grant/operation. Both
protected-file opens failed with permission errors and Finder's AX role was not
readable. Restoring that identical executable under Verity restored access without
further approval. This distinguishes host responsibility from old Python grants.

Additional runs: 13 unit/subprocess tests passed on both Python 3.11 and 3.14.
The original seven phase-1 checks plus three runner regressions passed again
against the preserved phase-1 app. On the expanded host, three blocked-worker
cleanup tests and three failure/termination/spawn regressions also passed.
Counts describe separate suites, not one combined assertion count.

## Important limits

- **Location remains not determined.** A consent request was attempted, but no
  coordinates were requested. This category is not part of the passing gate.
- The **system-wide focused-application AX read returns -25204**, even with trust.
  Finder's AX role succeeds under Verity and fails bare; this proves a narrow
  cross-process AX operation, not every desktop automation operation.
- **Local Network connectivity works, enforcement/identity continuity is unproven.**
  Four host/Python combinations connected to one selected on-link TCP endpoint
  without application payload. No Verity row appeared in the actual Local Network
  Settings pane, so no lab-only deny/allow control was possible. The selected
  endpoint was verified on-link via en0, not loopback or a routed Internet target.
  Do not infer permission enforcement from connection success. Apple's
  [TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy#Build-time-considerations)
  recommends an Apple-issued signing identity for reliable Local Network tracking;
  the local lab signer is not one. The observed behavior alone does not establish
  the cause of the missing Local Network row.
- Initial Photos request emitted authorized then its worker crashed. The request
  was not counted as clean success. Independent fresh status checks on both Python
  versions passed. The request-time crash cause remains unresolved.
- Settings Quit & Reopen interrupted a consent run; that receipt is unsuccessful.
  Fresh check-only processes verified the persisted grants afterward.
- No actual screen capture/input monitoring, full Hermes runtime compatibility,
  controller integration, production role tests, logout/login, or reboot proof.

## Settings registration defect found and fixed

The installed Swift compiler's default target was `arm64-apple-macosx28.0`, while
this host runs macOS 27. The lab Mach-O contained `LC_BUILD_VERSION minos 28.0`.
LaunchServices flagged it `unsupported-format`; registering returned success but
`NSWorkspace.urlForApplication(withBundleIdentifier:)` returned nil. Settings
saved FDA grants yet hid the row because it could not resolve the application URL.
An identical copy under Applications did not resolve the problem.

Compiling with explicit `-target arm64-apple-macos14.0`, re-signing with the same
lab key, and registering at the original hidden lab path made URL lookup succeed.
Refreshing System Settings then displayed the enabled FDA row and the other lab
permission rows. This was a build-target defect, not evidence that hidden paths or
self-signed FDA grants are categorically unsupported. No TCC resets/edits occurred.
All three builder scripts now pin the deployment target. The live expanded gate
checks the resulting Mach-O minimum version.

The temporary Applications copy was removed from Applications into the lab's
`registration-failure/` evidence archive. Unsupported builds and intermediate
pre-AX-operation evidence remain archived; phase-2 builds one/two and its reports
remain unchanged. Final supported generations are three/four at the existing lab
path. Do not overwrite the phase-2 report with expanded results.

## Independent review and regression fixes

Four new regression tests failed on the pre-fix implementation, then passed:
Calendar write-only → full-access upgrade, no protected-content reads, live
request-progress forwarding, and special-purpose network-address rejection.
The supervisor now drains and validates worker JSON while each worker runs; a
requesting event alone is not completion. `run_probe.py` still prints its summary
at exit; live progress is available in the run's `stdout.jsonl`.

A controlled hard-deadline test exposed **12 surviving workers** after the native
host killed only the Python supervisor, despite launchd bootout succeeding. Those
exact lab workers were terminated and verified gone. The host now verifies that
Foundation created a separate child process group, and kills that owned group on
hard deadline, forced termination, or supervisor exit. Host state and termination
callbacks are serialized on the main queue. All three blocked-worker cases now
pass (supervisor SIGTERM, SIGINT, native hard deadline), verifying every worker,
supervisor and host PID disappeared. This is not a promise for descendants that
leave their process group, or a host externally killed with SIGKILL.

Network validation is now RFC1918-only, with route/interface/subnet checks before
both building and connecting. The lab intentionally supports directly attached
`en*` interfaces with an available DHCP subnet mask; routed/VPN, special-purpose,
broadcast, and local-self addresses fail closed. It does not monitor route changes
during an already-running connection attempt. Four hosted connectivity cases pass
with this guard; Local Network enforcement remains unproven.

Earlier probes read one byte using buffered I/O, which can prefetch more than one
byte. They emitted no database content, but that read was unnecessary. The revised
probe proves read-open authorization without content collection. Older artifacts
and failed cleanup evidence remain in `pre-review-fixes/` and
`pre-group-cleanup-fix/`, not rewritten into successful runs.

## Reproduction and artifacts

Run only in the explicitly approved disposable lab with its existing signer,
matching native bridges, and operator-approved grants. Do not use production
Python grants as attribution evidence. No concurrent runs against the fixed lab ID.

```sh
# New expanded artifacts only: refuses existing output paths.
python3 experiments/verity_identity/build_permissions.py \
  --root "$LAB" --identity "$IDENTITY_METADATA" \
  --address "$ON_LINK_IPV4" --port "$TCP_PORT"
# Select an expanded build with verify_signed_live.select before requests.
# Have the operator present; request can last several minutes.
python3 experiments/verity_identity/run_probe.py --root "$LAB" \
  --mode permissions-request --timeout 550
# Check-only, asserts exact statuses and bare negative control:
python3 experiments/verity_identity/verify_permissions_live.py --root "$LAB"
# Dummy workers only; no permission APIs:
python3 experiments/verity_identity/verify_workers_live.py --root "$LAB"
python3 -m unittest discover -s experiments/verity_identity -p test_probes.py -v
```

Existing local evidence root: `~/.hermes/experiments/verity-identity-p2/`:
`expanded-build-report.json`, `expanded-verification.json`,
`network-connectivity.json`, `worker-verification.json`,
`expanded-runner-verification.json`, and referenced `runs/*/receipt.json`.
Raw local receipts, privacy metadata, and signing material are not committed.

**Decision:** expanded TCC attribution/continuity is demonstrated within the above
scope. Production remains **no-go** until remaining required exceptions are resolved
or explicitly accepted, controller integration passes isolated tests, and a separate
cutover is approved. No production credentials or messaging services were launched.
