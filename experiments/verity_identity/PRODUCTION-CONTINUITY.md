# Final-production-identity continuity (review required; not executed live)

`verify_production_continuity.py` is a separate bounded experiment. It does not
modify the existing permission harness, frozen Swift/probes, stager, controller,
installed controls, or any previously prepared root. This implementation has only
been exercised with disposable fixtures and mocked operating-system boundaries.
**No final-identity continuity pass or cutover readiness is claimed.**

## Fixed scope

One permission is sealed per fresh root. The immutable order is:

| Build epoch | Synthetic role | Worker ABI order |
|---|---|---|
| A | agent, then webui | 3.11, then 3.14 for each role |
| B | agent, then webui | 3.11, then 3.14 for each role |
| A rollback | agent, then webui | 3.11, then 3.14 for each role |

There are twelve cases. `agent` and `webui` are **synthetic host arguments**, not
real gateway/WebUI processes or their descendant chains. No application server,
port, network operation, launcher/controller import in children, or production
service restart is part of this experiment. Different permissions require fresh
roots; this is not an all-permission batch runner.

The allowlist is the thirteen previously allowed observations (Messages/Safari
read-only descriptor open/close, Accessibility plus fixed Finder AXRole, Input
Monitoring, Screen Capture, Contacts, Calendar, Reminders, Camera, Microphone,
Photos, Speech, Bluetooth) plus **Automation: Finder**. Finder uses the base
harness's authorization-only implementation and its strict OSStatus schema,
never AppleEvent delivery/window enumeration. All cases are `permissions-check`;
there is no request flag, worker/role/command override, alternative compiler flag,
endpoint, arbitrary ABI, or runtime override at run time. Location, Location
Diagnostic, and Local Network are excluded, not declared resolved.

Permission authorization is not authorization to perform a user task. A denied,
unknown, limited, incomplete, malformed, or requesting result cannot produce a
continuity pass. The matrix stops at the first unsuccessful case. Full-access
Calendar/Reminders and authorized Photos are required, rather than treating a
limited grant as full continuity. FDA open errors likewise fail the matrix.

## A/B code-change contract

The original installed bundle is strictly signature-checked against the existing
production requirement and canonical `production_info_plist()` bytes. Build A
reuses its native executable, and retains the base `code_payload()` comparison:
**every byte before the trailing embedded signature must match the installed
host**. No existing comparison or helper is weakened.

Build B compiles an unchanged copy of the same frozen `ServiceHost.swift` using
the stager's fixed arm64/macOS14/Swift5 invocation with exactly one additional
flag: `-O`. Compiler HOME, temporary files, module caches, Hermes state, and WebUI
state are disposable directories inside the new experiment root; inherited
compiler variables are not used. Source bytes are rechecked after compilation.
There is no fallback to source edits or another optimization when the text does
not differ.

The new narrow Mach-O reader requires a thin arm64 executable and exactly one
executable `__TEXT,__text` section with instruction attributes and valid file
bounds. A/B section SHA-256 values must differ. UUID changes or a different
signature alone do not satisfy the gate. Text bytes must survive each signing
operation unchanged. A freshly linked B can need a different signature allocation,
so B is not compared to A with the copy-only comparator; its **final complete
bundle inventory** is separately sealed and checked before every use. A's strict
copy-only comparison is unchanged.

Both builds are signed during preparation with the existing production signer,
requirement, and identical canonical Info.plist and service-settings bytes. Both
are staged before any run. No signing or settings mutation occurs during ABI/role
switches or rollback. The code-change scope is **compiler optimization of the
same host source**, not arbitrary source changes, toolchain upgrades, framework
updates, notarization, certificate changes, or whole-app upgrades. Real compilation,
code-signing compatibility and actual executable-text difference remain untested
here; a real preparation must prove them or stop.

## Runtime and launcher sealing

A single root launcher is hashed into both builds' signed settings. It embeds the
entire finite config table and accepts only the frozen host's exact role/manifest
argv. It selects the unique unfinished append-only case intent in order. No mutable
config file supplies a child command. Each case has an independent copied executable,
worker launcher, probe copy, HOME/state/TMPDIR/WebUI state, output, nonce and GO.
Worker invocation is fixed to `-S -s -P -u -B CASE/production_launcher.py --worker`.
The worker verifies its ABI and the base nonce/GO protocol before importing the
explicit native bridge and invoking the selected check-only worker.

The approved bootstrap interpreter remains the explicit existing bootstrap, as
in the base harness; the permission-worker executable is freshly copied for every
case. This does **not** promise a relocated standalone Python distribution or
prove the absence of equivalent-code OS grants. Explicit runtime homes and bridge
trees are inventoried without executing/importing them. Contents, owners, modes,
and internal file-link targets are pinned, along with copied worker/launcher/probe
hashes and the bootstrap executable hash. Directory links and escaping links
refuse. Runtime/bridge dependencies and sealed inputs are checked in preflight,
before each bootstrap, and again before GO. The bootstrap's transitive standard
library and platform dynamic libraries are not a hermetic runtime seal. An explicit
input distribution incompatible with these constraints must be reviewed/repackaged
separately; do not bypass refusal by weakening the inventory.

## Operator phases (separate approvals)

These are interface examples for the parent after focused review, **not commands
executed by the implementation child**. Supply already approved explicit paths;
do not discover credentials, import a real bridge, or inspect installed artifacts
to guess them during offline development.

```text
python -B verify_production_continuity.py prepare \
  --root ROOT --base BASE --home HOME --python APPROVED_BOOTSTRAP \
  --runtime311 PYTHON311_HOME --bridge311 BRIDGE311 \
  --runtime314 PYTHON314_HOME --bridge314 BRIDGE314 \
  --permission 'Camera' --approve-sign

python -B verify_production_continuity.py preflight --root ROOT

# Separately approved bounded live experiment, not production activation:
python -B verify_production_continuity.py run --root ROOT --live

# Cleanup/reconciliation only; never resumes matrix execution:
python -B verify_production_continuity.py recover --root ROOT --live
```

ROOT must be new, directly inside the existing safe `HOME/.hermes/experiments`,
on the same filesystem as Applications. BASE must contain the already-provisioned
safe shared `control.lock`. Existing roots are never reused, edited, repaired,
re-signed or deleted. The expected final path is `HOME/Applications/Verity.app`,
with the existing base production signer/requirement. Passive registration is a
separate prerequisite; this harness never launches a real app to register it.

Preparation has its own durable start receipt before copying/building. Failed
preparations retain partial artifacts, never publish `prepared.json`, and never
move the original. Preflight verifies sealed artifacts/signatures but performs no
launchd or permission operation.

## Ownership, cleanup and recovery

Run holds the shared nonblocking production lock through admission, swapping,
all cases, cleanup, and restoration. It retains exact legacy selector/plist
snapshots and checks the existing native-dependency admission helper. It never
changes production selection, production job definitions or production jobs.

A durable swap receipt precedes moving the original to `ROOT/original.app`.
The original is never re-signed or used as the rollback-A staging slot. Each build
transition has an append-only intent, and staged A/B bundles move by rename to
and from the exact final path. Complete inventory and strict final-path signature
checks precede each bootstrap. Each case's durable bootstrap intent identifies
its exact unique experiment target before any launchctl mutation.

The gate checks actual loaded-job PID plus kernel PID, PPID, UID, executable,
full argv, birth time, process group, and the guard chain. It validates the running
host's certificate-pinned signature and repeats kernel identity observations.
Only then can the per-case GO echo that worker's fresh nonce and identity. Clean
worker, supervisor, host-child and launchd-host exits are required. Output has a
closed event schema, unique events, a small record/byte bound, and the base's
sanitized permission scalar schema.

Cleanup addresses only recorded exact experiment targets. Neither bootout success
nor a FakeLive boolean is enough: target absence, disappearance of recorded PIDs
and PGIDs, and an independent same-user kernel executable/argv census are checked.
The census catches artifact users even before the first process event. Unreadable
live identities, census failure, malformed output or drift refuse restoration;
this version conservatively refuses unreadable zombies as well. No raw process
argv/environment or exception text is published.

Ordinary errors and a first SIGINT/SIGTERM enter cleanup and restoration. If cleanup
is unknown, the original stays separately retained rather than moving a bundle
under an unaccounted process. Recovery cleans intended targets **before** checking
legacy snapshot drift, and requires no legacy service uptime/dependency check.
It does not regenerate old launchers or need both staged variants present. Renames
are reconciled from exact original/A/B inventories. Restoration verifies the
original inventory and strict signature at its final path. Nothing is deleted.

There is no guaranteed automatic restoration after SIGKILL, repeated interrupt,
filesystem failure, arbitrary same-account interference or power loss. Preserve
the root and reconcile with `recover`; fail-closed retention is not a restored
result. An unknown or foreign final-path inventory requires manual review, not
forced overwrite. Advisory locking and file hashes are not a hostile same-UID
sandbox. Recovery cannot restore or revoke OS permission decisions.

## Offline verification

Tests run with fresh disposable HOME/HERMES_HOME/HERMES_WEBUI_STATE_DIR/TMPDIR
and a minimal per-subprocess environment under the configured scratch directory.
The new tests use real filesystem writes/renames and the actual matrix/identity/
cleanup validators. Only OS observation/command boundaries are mocked. Compiler
and signer runners operate on tiny fixture Mach-O containers, not executable host
code. Subprocess/network tripwires protect the offline boundary; generated worker
and supervisor entry points are also executed with mocked child/probe interfaces.

```text
python -B -m unittest test_production_continuity test_production_permissions \
  test_install_production_native test_stage_production_native -q
```

Python 3.11 and Python 3.14 each passed **113 tests**, including **15 new continuity
tests** and the base permission/install/stage neighbors. Coverage includes full
A/B/A ordering, unchanged settings and original restoration, actual identity-field
rejection (not an unconditional fake identity pass), copied-runtime and bridge
drift, strict Finder status integration, nonce/worker entry points, mid-build and
mid-sign failures, post-rename failures across swaps, durable intent/GO/result
failures, pre-first-event bootstrap failure, supervisor exit failure, cleanup
retention and recovery, and independent artifact-user/unreadable-identity refusal.
An initial test run reproduced launcher regeneration drift caused by dictionary
ordering; canonical config ordering fixed it. Changed-file Ruff checks passed.

These are offline tests, not compiler/signing/launchd/TCC attribution evidence.
The parent independently froze the delivered files over committed controller
`5ba4734d89b4bb7291474d837761ef1d9a102a2c` and ran the 113-test aggregate plus
five cutover-recipe fixtures: **118 tests passed on each ABI**, with matching
repository Ruff configuration. Concurrent return-to-baseline controller edits
were excluded from that snapshot. The parent then extended preparation fault
coverage to explicitly reach and identify A signing, B compilation, and B signing;
all three injection points preserve the original and withhold prepared publication.
The 113-test aggregate also passed on each ABI after that fault-coverage
extension, in a fresh frozen snapshot. Focused independent execution-contract
and cleanup/recovery reviews are pending;
no live preparation or permission run is authorized by these unit results.

Real final-path execution remains for the parent after focused review and explicit
bounded-live approval. No compile, signing, permission API, launchctl, service
operation, network connection, installed-artifact inspection, commit or push was
performed by this implementation task.
