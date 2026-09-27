# Phase 2: persistent signing and runtime continuity

## Question and decision

Can a persistent native identity keep the tested permissions when both its own
executable bytes and the child Python minor version change?

**Yes in this isolated macOS 27.0 experiment. Go to expanded permission/controller
testing; not to production cutover yet.** All seven signed-continuity checks
passed. The seven phase-1 attribution checks and three runner regressions also
passed again. These are local, opt-in integration tests, not a full Hermes CI run.
Ruff lint and changed-Python-file format checks pass. The all-directory format
check still flags the unchanged `probe.py` from phase 1; it was deliberately not
reformatted after being embedded in the signed test artifacts.

## Signing setup and boundaries

The operator explicitly approved a dedicated **Verity Lab Code Signing** identity
in the login Keychain. The import requested a non-extractable private key with
`security import -x -T /usr/bin/codesign`. The temporary private-key file was
removed; private material was not logged or committed. No export/recovery test
was performed. This lab identity is not a production recovery strategy.

The certificate has digital-signature/code-signing usage and `CA:FALSE`. User-domain
trust was separately approved and read back as exactly one **Code Signing** policy.
No SSL trust, system-domain trust, TCC reset, or privacy-database edit was used.

The new app is **Verity Signing Lab**, `com.charles.verity.signinglab`, separate from
phase 1 and the proposed production identity. Each of two independently compiled
host revisions is signed with the same certificate-pinned designated requirement:

```text
identifier "com.charles.verity.signinglab" and certificate leaf = H"<certificate SHA-1>"
```

Their executable SHA-256 hashes differ. Revision `two` is compiled with
`REVISION_TWO`; live host events identify which binary actually ran. Both bundles
pass strict signature verification against the same requirement. A valid ad-hoc
copy with the same bundle identifier fails that requirement. This is a codesign
negative control, **not** an attempt to launch an impostor or test TCC against one.

Both signed builds were prepared before the first grant, then installed in turn at
one fixed lab path. No signing occurs during selection, permission checks, or
rollback. This proves cross-build continuity, not update-package or notarization
behavior. The app bundle is staged/copied and signature-checked before use;
parked prior copies remain inert under the lab root.

## Live verification

A no-request baseline initially showed camera not determined and Finder requiring
consent for the new identity. The operator then approved the camera and Finder
prompts under **Verity Signing Lab**. Every verification run below uses check mode
and requests no new grants:

| Case | Host | Python | Observed |
|---|---|---|---|
| Initial | one | 3.11.16 | Camera authorized; actual Finder operation succeeds |
| Changed native binary | two | 3.11.16 | Same permissions still work |
| Minor-version swap | two | 3.14.7 | Same permissions still work |
| Bare negative control | none | exact same 3.14.7 copy | Camera not determined; Finder requires consent |
| Hosted again | two | exact same 3.14.7 copy | Permissions work again |
| Host rollback | one | 3.11.16 | Permissions still work |
| Host rollback, newer Python | one | 3.14.7 | Permissions still work |

Each case uses fresh processes. Hosted receipts establish launchd → native host →
Python ancestry; the bare copy has parent PID 1. The runtime paths are independent
copies, with no direct Python grants requested. Python 3.14 support here means
**permission-probe compatibility**, not full Hermes application compatibility.

Camera verification is authorization-status only: no media capture. Finder's
read-only window-count Apple Event runs through Python's `osascript` descendant,
with output discarded. This is not direct Python Apple Event evidence. Other
privacy preflights are recorded but not counted as granted. In particular, the
protected-file open remains denied for the ungranted lab app.

The installed lab bundle is restored to revision `one`; all disposable jobs are
unloaded. Production launcher/selection/plist hashes, WebUI/gateway job PIDs, and
health match the baseline taken before this signing test phase. There is no
persistent lab login job and no production restart or cutover.

## Reproduction (operator-supervised, lab only)

Read the phase-1 safety and runtime-layout constraints in [README.md](README.md).
Use fresh roots outside Git. Do not run two test runners concurrently for the
same bundle ID, and do not use `python -O` (the harness uses assertions).

1. With explicit operator approval, create the lab key in an unused directory:

   ```sh
   python3 experiments/verity_identity/create_lab_identity.py --root "$SIGNER_ROOT"
   ```

   This helper does not add trust. On the tested macOS, traditional RSA PEM from
   `/usr/bin/openssl genrsa` imported successfully; the PKCS8 form generated by
   `req -newkey` was rejected by `security import -f openssl`.
   Do not rerun into another root merely to address an untrusted identity: retain
   the same key/certificate. Interrupted partial imports need inspection, not a
   blind retry. This helper is not transactional keychain provisioning.

2. With separate approval, add **user-domain Code Signing trust only** and verify:

   ```sh
   security add-trusted-cert -r trustRoot -p codeSign \
     -k "$HOME/Library/Keychains/login.keychain-db" "$SIGNER_ROOT/certificate.pem"
   security find-identity -v -p codesigning
   security dump-trust-settings
   ```

   Any password belongs only in the macOS system dialog. The creation-time
   `identity.json` records that the helper itself did not change trust; it is not
   a current trust-status receipt.

3. Provide existing standalone Python distributions and matching PyObjC bridges;
   the builder does not install dependencies or modify source interpreters:

   ```sh
   env -u PYTHONPATH -u PYTHONSAFEPATH python3 experiments/verity_identity/build_signed.py \
     --root "$LAB" --identity "$SIGNER_ROOT/identity.json" \
     --python311 "$PYTHON_311" --python314 "$PYTHON_314" \
     --bridge311 "$PYOBJC_311" --bridge314 "$PYOBJC_314"
   python3 experiments/verity_identity/run_probe.py --root "$LAB"
   ```

   If the initial identity already has grants, disclose that the clean baseline
   was not reproduced. Do not erase existing grants to manufacture one.

4. With the operator present, request camera and Finder separately. After a
   timeout, check state before re-requesting:

   ```sh
   python3 experiments/verity_identity/run_probe.py --root "$LAB" --mode request-camera --timeout 230
   python3 experiments/verity_identity/run_probe.py --root "$LAB" --mode request-finder --timeout 230
   python3 experiments/verity_identity/verify_signed_live.py --root "$LAB"
   ```

5. Read `build-report.json`, `signed-verification.json`, and all case receipts.
   Verify no `com.charles.verity.signinglab.probe` job remains and compare the
   existing production baseline. A signature alone is not permission evidence.

Generic source lives on the experiment branch; local certificates, keys, runtime
copies, absolute host paths, process logs, and raw TCC data do not belong in Git.
The lab signer is intentionally retained for reproducibility; creating another
signer on every build would destroy the property being tested.

## Remaining gates

- Full Disk Access, Accessibility, Input Monitoring, screen capture, native data
  APIs, microphone, Bluetooth, Location, and especially **Local Network**.
- Local Network's behavior under local signing must be measured; Apple-issued
  signing guidance is not superseded by two successful TCC categories.
- Both real service-role descendant chains, strict restart-controller ownership
  checks, failure/rollback integration, and independent WebUI/gateway restarts.
- Logout/login, reboot, certificate renewal/replacement, key recovery, and any
  macOS policy changes. None was tested here.
- Production-grade validation of external runtime/bridge/selection inputs and
  arbitrary child-tree supervision. These are controlled lab fixtures today.
- Explicit permission-batch and cutover/restart approval for the final production
  identity. Existing Python grants are not renamed, copied, or removed.

The broader architecture and rollout remain separate work. This branch is a
repeatable experiment, not an installed solution to every macOS permission prompt.
