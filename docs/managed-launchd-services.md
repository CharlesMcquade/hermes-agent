# Externally managed gateway LaunchAgents

A deployment manager can retain ownership of a gateway plist by adding this
**top-level** property (shown as Python data before `plistlib.dump`):

```python
"HermesServiceManager": {
    "preflight": ["/absolute/python", "/absolute/launcher.py", "agent", "--check"],
    "description": "Use managed production deployment to change this service",
}
```

The marker is local executable configuration: install it only from a trusted
manager. `preflight` must be a nonempty array of nonempty strings, with an
absolute executable as its first argument. `description` must be a nonempty
string. Hermes executes the argv directly, without a shell, with closed stdin
and a 60-second timeout. The manager's check must be read-only, return zero only
when its launch target is ready, and report failures on stderr.

- `hermes gateway install`, including `--force`, refuses to replace the definition.
- Automatic plist refresh preserves it and prints the ownership description.
- Start and restart run preflight before any launchctl action or request for the
  running gateway to stop. A failed, missing, or timed-out executable prevents
  the lifecycle operation. Invalid marker values also fail closed.
- Launchctl failures do not fall back to an unmanaged detached gateway. Repair
  the deployment or launchd domain through the owning manager instead.

Unmarked plists retain normal Hermes installation, refresh, and fallback
behavior. This contract does not change explicit stop or uninstall semantics;
it is not a lock against an administrator removing the service. Preflight is a
readiness check, not a deployment transaction: the manager remains responsible
for publishing stable launch targets and avoiding concurrent target changes.
