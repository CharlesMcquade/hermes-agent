# Production readiness: signer complete; native integration verified in part

The reviewed isolated gates are complete; see `COMBINED-CANARY.md`. They do
not constitute a production cutover-ready artifact. The operator requested
completion through readiness, with notification only at readiness or a genuine
blocker. Production selection, service restarts and reboot remain unapproved.

## Production signer and recovery gate

The operator approved a dedicated production signing identity, code-signing-only
trust, and encrypted 1Password recovery. 1Password for Mac 8.12.36 is installed at
the explicitly requested `/Applications/1Password.app`; CLI 2.39.0 is installed at
`/opt/homebrew/bin/op`. Both signatures verified. Desktop sign-in and CLI integration
are now verified. Headless and PTY authorization timed out; the user approved a
native request from a dedicated Terminal.app tab, after which vault access passed.
This successful alternative does not isolate the cause of the headless timeout.

`create_production_identity.py` generated a new RSA production identity in memory,
saved encrypted PKCS8 and its strong passphrase in concealed fields of the explicitly
selected Private vault (not Shared), then fetched the exact item by vault/item ID.
Every recovery field matched, decryption succeeded, and a signing challenge verified
against its certificate. Only the recovered key was written to an owner-only
transient file and imported non-extractable with the codesign ACL; that file is gone.
The operator approved macOS's trust request. Read-back shows exactly one trust policy,
CodeSigning, in the user domain. An actual copied Mach-O was signed using this restored
key, verified against its leaf pin, and executed successfully.

Public production certificate SHA-1: `B72A53676319B035EF637A6DEF27F026009D989C`.
Nonsecret local checkpoint: `~/.hermes/signing/verity-production-v1/identity.json`.
Recovery item identifiers stay in that local checkpoint, not in tracked source.
No secrets were printed or passed in command arguments. The initial source review
found two blockers: partial-key writes were outside the cleanup boundary, and trust
validation checked the name without the policy identifier. Two regression methods
reproduced five failing subcases on the original code (partial write/close and three
invalid identifiers). Serialization/write now sit inside `try/finally`, and trust
validation requires exact `CSSMOID_APPLE_TP_CODE_SIGNING` bytes (`2a864886f763640110`).
The constant was independently compared with Security.framework's exported symbol;
a fresh user-domain trust export passes the stricter validator. The real transient
key file remains absent. No repro used actual private material or Keychain writes.

Eight signer tests (including ordinary serialization/write/close/checkpoint/import
failure paths) and all 37 affected/neighboring experiment tests pass on Python 3.11;
changed-file Ruff checks pass. This does not claim cleanup survives process kill,
OS crash, or filesystem unlink failure. Independent focused re-review found no
blocking findings in scope, confirming both fixes and their regression coverage.
The signer/recovery gate is complete. Production host/control staging and final-
identity permission validation remain unfinished; this is not cutover readiness.

## Previously identified signing prerequisite

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

## Native environment and migration integration

The optional signed bootstrap environment and narrow legacy-to-native definition
migration are implemented. The stager now supplies explicit HOME/TMPDIR and the
common selected HERMES_HOME without altering selected source/runtime dictionaries.
Offline migration tests prove exact manifest and binary-plist rollback on failed
native readiness. A lab-only live environment gate passed 70 cases across both
roles, with independently verified process/group/job cleanup; see
`PRODUCTION-STAGING.md` for evidence and two retained harness failures/fixes.
These are not final production identity, installation, messaging or cutover tests.
Environment/staging integration review reported only the already-fixed cleanup
finding and no other blockers. The new synthetic migration harness passed six live
cases with independent cleanup verification and unchanged production baseline;
see `../../NATIVE-MIGRATION-CANARY.md`. Its current-source review remains pending.

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

The approved new certificate, its restored Keychain key, and code-signing-only trust
have been provisioned. No final app installation, production-control write, launchd
definition change, final-app permission request, release selection, or production
restart has occurred. The production baseline still returns hashes/PIDs/health
unchanged and health `ok`.
