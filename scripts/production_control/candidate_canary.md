# Isolated candidate runtime canary (macOS)

Run with a staging interpreter, never the live frozen runtime. Supply explicit
self-contained agent/WebUI Git checkouts, runtime, and full lowercase commit SHAs.
Source directories must be `agent` and `webui` siblings of the private `runtime`,
and the interpreter must be `runtime/venv/bin/python` (also for isolation-only runs):

```sh
PYTHONDONTWRITEBYTECODE=1 /path/to/staging/python -B scripts/production_control/candidate_canary.py \
  --python /path/to/candidate/runtime/venv/bin/python \
  --runtime /path/to/candidate/runtime \
  --agent /path/to/candidate/agent --agent-sha FULL_AGENT_SHA \
  --webui /path/to/candidate/webui --webui-sha FULL_WEBUI_SHA
```

The CLI prints a retained `report.json` path below `~/.hermes/cache/scratch/canary-*`.
Exit zero plus `status: passed` proves two actual boot cycles (cold start and
stop/relaunch), expected gateway runtime SHA/PID/home, deep WebUI health,
loopback listener ownership, five served asset digests, and unchanged candidate
inventories including Git metadata and bytecode caches. All created process groups
are stopped; disposable application state is removed. Logs and policy are retained.
Cleanup uses a retained descriptor for the freshly owned scratch run and only
removes `home`, `state`, `webui`, and `tmp`. Nested read-only copied skill directories
are made owner-writable through verified no-follow directory descriptors; files
are never chmodded, symlinks are unlinked without following, and mount crossings
are refused. Removal is skipped if child shutdown is not proven. Each removal is
attempted independently, and the receipt records remaining entries and cleanup
errors without replacing the original runtime exception. Incomplete cleanup
forces failed status and nonzero exit, even after successful health checks.
Receipts are atomically replaced and fsynced. If storage itself fails, certification
still fails and the report is emitted to stderr; durable storage cannot be guaranteed
in that case.
This does **not** validate launchd, production restart buttons, native host integration,
provider inference, or message delivery. It never selects a release or controls services.

The environment is constructed without inherited credentials. Before application
launch, real parent/child probes must demonstrate denied out-of-run file reads/writes,
unrelated loopback/external connections, and shell execution. Candidate processes
are OS-contained by `sandbox-exec`: writable only inside fresh state, only the chosen
loopback listener and state-local Unix sockets permitted. The policy allows Apple's
CommandLineTools read dependencies and exact Git executable because `/usr/bin/git`
is an xcrun shim; omitting these hides authentic runtime code identity. The single
public `/private/etc/apache2/mime.types` file is needed for Python static asset serving.
Do not fix identity failures by injecting SHA env values or relaxing equality checks.
Unsupported sandbox/toolchain installations fail closed.

Tests use stdlib unittest and disposable fixtures, not product pytest:

```sh
PYTHONPATH=scripts/production_control PYTHONDONTWRITEBYTECODE=1 \
  /path/to/staging/python -B scripts/production_control/test_candidate_canary.py
```

The OS tests currently require Apple's CommandLineTools Python and Git installation.
Use short scratch paths: macOS AF_UNIX paths have a small fixed limit.
