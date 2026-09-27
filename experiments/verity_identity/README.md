# Verity native identity: isolated experiments

**Not a production launcher. Do not merge or deploy as one.** This branch preserves
three experiments and their repeatable probes. None modifies Hermes startup,
release selection, application credentials, or configuration. Phase 2 explicitly
creates an operator-approved lab identity in the login Keychain.

## Current outcome

**Expanded TCC continuity passed; no production cutover yet.**
Seven expanded cases now cover FDA protected opens, a real Finder AX-role read,
and authorization/preflight for the remaining granted categories across host
rebuild, Python 3.11 → 3.14, a bare negative control, restoration, and rollback.
Location and Local Network enforcement remain unproven.
See [Phase 3: expanded permissions](EXPANDED-PERMISSIONS.md) for precise scope,
limitations, and the fixed compiler-target/Settings-registration defect.
[Phase 2](SIGNED-REBUILD.md) preserves the prior narrower result.
The sections below describe phase 1 only.

## Question

Does a native app, kept alive above changing Python executables and launched by
user launchd, provide a usable macOS permission identity for those children?

## Phase 1 result on macOS 27.0

**Go to persistent-signing prototype; no-go for production deployment yet.**

The operator approved camera authorization and Finder automation for **Verity
Prototype**, bundle ID `com.charles.verity.prototype`. Seven live checks passed:

| Check | Observed result |
|---|---|
| launchd → native host → Python A | Host parent PID 1; child parent is host; camera status authorized; Finder window-count Apple Event succeeds |
| Substitute independently copied/signed Python B at another real path | Same authorization and successful Finder operation, without another request |
| launchd → the same Python B, without native host | Camera not determined; Finder authorization requires consent |
| Python exits with 23 | Native host and launchd report exit 23 |
| SIGTERM to native host with sleeping child | Child receives termination; neither host nor child survives job removal |
| Python B under native host again after negative control | Both approvals still effective |
| Unsupported native-host mode | Rejected with exit 64 before launching a child |

Both Python copies were 3.11.16. Different absolute paths, distinct files/inodes,
and distinct copied-interpreter code-signing identifiers were used. No direct
permission grant was requested for either Python. The negative control helps rule
out existing Python permissions as the cause of success. It does **not** isolate
which individual launchd plist property makes app attribution work.

Camera verification is **authorization-status only**; no camera session was
opened and no images/audio were captured. Finder verification used a real,
read-only window-count Apple Event from Python's `osascript` child, with
stdout/stderr discarded. This establishes the descendant-chain operation, not a
direct Python implementation of the Apple Event. A protected
Messages file open was denied, as expected for this ungranted prototype; its
contents were not exposed. Screen/AX/input checks were false and were not granted.

The production WebUI/gateway PID baseline, production launcher/manifest/plist
hashes, and health were unchanged after the experiment. All disposable launchd
jobs were removed after their runs. The inert prototype bundle and local receipts
were retained for follow-up; it is not installed as a login/startup job.

## Review follow-up

The independent review examined an intermediate working snapshot. Its missing
bare-Python control finding had already been resolved and exercised in the
committed version. Two current runner issues were reproduced/addressed:

- Wait for launchd to report the stopped host and its final exit status, rather
  than treating a child-exit log line as process exit. The CLI now returns the
  observed failure code; a failed child spawn cannot look successful.
- Handle runner SIGTERM/SIGINT by requesting cleanup, rather than letting Python
  terminate before `finally`. The signal is deferred across bootstrap so a
  successfully registered job is not lost between registration and cleanup.

Three additional live regression checks pass: CLI failure propagation (23),
missing copied interpreter/spawn failure (70), and SIGTERM to the runner while
its host/child are alive (143, job unloaded and both processes gone). The first
regression failed on the old runner with `('fail', 0, 23)`. All seven original
checks then passed again. The signed native app/probe were not rebuilt or changed.

A runner exit of zero means the check completed, **not** that every reported
permission is granted. The live verification harness checks the required values.
SIGKILL cannot execute cleanup; a runner killed that way can leave the inert job
registered. The host lifetime is bounded, but automatic cleanup after SIGKILL is
not a tested guarantee. Do not run concurrent sessions against this fixed lab ID.

## Phase 1 limitations

- The app is **ad-hoc signed**. Its designated requirement is tied to its code
  hash. It is not a persistent signing identity; host-rebuild continuity was not
  tested and must not be inferred from child-path continuity.
- No 3.11 → 3.14 swap, full permission batch, Local Network, Location, reboot,
  logout/login, production service role, or controller integration was tested.
- No general child-tree/crash supervision contract is established. The narrow
  SIGTERM test covers the single sleeping Python child, not arbitrary
  grandchildren, detached processes, or an uncatchable host SIGKILL.
- This does not provide another app/daemon's independent grants.
- Input metadata and external interpreter/bridge files are controlled experiment
  fixtures, not a hardened production trust boundary.

Phase 2 subsequently tested persistent signing, a rebuilt host, and the Python
minor-version swap; see [SIGNED-REBUILD.md](SIGNED-REBUILD.md). Expanded permission
coverage and production migration remain separate, explicitly approved work.

## Files

- `Host.swift`: AppKit host; fixed modes and runtime slots; strips inherited
  credentials from Python's environment; native camera-consent request.
- `probe.py`: read-only status probes plus Finder automation. No Hermes imports,
  recording, protected-data output, or service startup.
- `build.py`: copies (never re-signs originals) a local Python executable into two
  experiment slots; compiles the host and creates an ad-hoc signed bundle.
- `run_probe.py`: temporary LaunchAgent registration, bounded execution, local
  receipt collection, and `finally`-based job removal. No persistent plist in
  `~/Library/LaunchAgents`; no KeepAlive/restart loop.
- `verify_live.py`: opt-in, prompt-free integration checks after operator consent.
  Not suitable for a normal unattended CI run. Fails rather than faking approvals.
- `verify_runner_live.py`: opt-in runner failure and interruption regressions; no
  permission requests. Temporarily parks/restores only the lab Python A copy.

## Reproduce on a disposable macOS test identity

Use a **new empty root outside Git**, an explicit local Python 3.11 interpreter,
and an existing matching PyObjC bridge directory. The Python distribution used
in the observed run is standalone (no non-system linked dylibs); arbitrary
framework/Homebrew Python copies may need different runtime layout. The host
and bundle ID are intentionally disposable and must not be confused with a final
`Verity.app` identity. Do not create multiple simultaneously registered copies of
this same prototype ID.

```sh
python3 experiments/verity_identity/build.py \
  --root "$LAB" --python "$SOURCE_PYTHON" --bridge "$PYOBJC_311"
python3 experiments/verity_identity/run_probe.py --root "$LAB"
# Have the operator present before these two bounded request runs:
python3 experiments/verity_identity/run_probe.py --root "$LAB" \
  --mode request-camera --timeout 230
python3 experiments/verity_identity/run_probe.py --root "$LAB" \
  --mode request-finder --timeout 230
python3 experiments/verity_identity/verify_live.py --root "$LAB"
python3 experiments/verity_identity/verify_runner_live.py --root "$LAB"
ruff check experiments/verity_identity
```

The observed camera request initially timed out before the callback returned;
the operator's later approval still persisted. A subsequent no-request run
verified it. Timeout is not denial, and a repeated full consent batch is not the
right recovery. Check saved state before requesting again. The current host has
a hard 240-second lifetime; `--timeout` cannot extend that limit.

Each run writes `runs/<unique-run>/receipt.json` plus JSONL stdout and stderr
beneath the lab root. The final integration harness writes `verification.json`
only after all checks pass. These local artifacts contain host paths/PIDs and are
**not committed**. Do not publish local logs or privacy database exports.

Do not reset/edit TCC, disable SIP, re-sign a live runtime, or restart production
in order to reproduce this experiment.
