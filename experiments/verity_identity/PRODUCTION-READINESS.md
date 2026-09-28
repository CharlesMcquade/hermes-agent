# Production readiness: blocked before final identity provisioning

The reviewed isolated gates are complete; see `COMBINED-CANARY.md`. They do
not constitute a production cutover-ready artifact. The operator requested
completion through readiness, with notification only at readiness or a genuine
blocker. Production selection, service restarts and reboot remain unapproved.

## Blocking dependency: production signing and recovery authorization

Read-only discovery returned exactly one valid code-signing identity:
`Verity Lab Code Signing`, SHA-1
`A17BCFC88CD3BB95555C22CB8B8FA36D4F6336CE`.
No usable Apple-issued identity was listed in the current keychain search context;
this is not evidence that the operator lacks an Apple developer account.

The existing certificate is self-issued and valid from September 27, 2026 through
September 24, 2036. The provisioning source imported its key with `security import
-x` (non-extractable), deleted the transient key file, and recorded a lab-only
purpose. No export was attempted, no private key was read, and no independent
recovery copy has been established. The prior approval expressly limited this
identity and code-signing trust to an isolated experiment, not production.

Do not silently promote that identity or try extracting its non-extractable key.
Resolve the explicit production signing decision first:

- An operator-approved Apple-issued identity with a verified recovery procedure; or
- A dedicated local production identity, code-signing-only trust, and an explicitly
  authorized encrypted off-device recovery destination. Create and validate recovery
  before destroying temporary provisioning material. Keep all private material and
  recovery secrets out of source, logs, argv, reports and chat.

The final bundle `com.charles.verity` at `~/Applications/Verity.app` needs its own
system consent. Existing lab grants are not production grants. Do not rename or
transplant TCC records. Provisioning/trust and consent require operator involvement;
no test can eliminate those approvals.

## Unfinished implementation and verification after that dependency

1. Stage the final fixed-path host and native-aware control bundle without
   selecting it. Preserve the existing frozen application pair and bootstrap
   runtime; do not slip in an unrelated application or dependency upgrade.
2. Adapt staging for the currently installed schema-2 controller. The inherited
   `install_controls.py` is a schema-1 migration only and its `FILES` list omits
   `native_identity.py`. The inherited `prepare_cutover.py` constructs Python
   launch arguments, not native host arguments, and uses shared candidate paths.
   Neither is a ready-made native-host production installer. Do not run either
   against maintenance as a shortcut.
3. Revalidate the exact final host, signed settings, control inventory, both roles,
   independent restarts and bounded rollback in isolation. Preserve unrelated
   pending candidates and job definitions. Extend permission-runner identity
   reporting to distinguish responsible native host from selected child Python.
4. Obtain the final identity's grants; test fresh paths, compatible minor-version
   permission workers, signed rebuild and rollback without resetting old grants.
   Resolve Local Network enforcement and Location, or obtain explicit acceptance
   of precisely documented limitations. A successful TCP connection alone is not
   Local Network consent/enforcement proof.
5. Prepare the exact candidate manifest, launchd definitions, independent
   activation job, and recovery material; verify they are unselected and unarmed.
   A fully tested stage is the point to request cutover approval.
6. After explicit cutover approval, verify the real application and messaging
   contexts. Logout/login and reboot need separately agreed disruption timing.
   Do not call process restarts a reboot test or start a second real gateway.

No new certificate, Keychain trust, final app installation, production-control
write, launchd definition change, permission request, release selection, or
production restart was performed during this readiness audit. The existing
baseline check returned hashes/PIDs/health unchanged and health `ok`.
