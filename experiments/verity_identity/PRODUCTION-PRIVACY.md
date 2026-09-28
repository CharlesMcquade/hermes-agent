# Production bundle privacy metadata (pre-cutover only)

`stage_production_native.py:production_info_plist()` is the authoritative complete
Info.plist for this production candidate. It supplies explicit production-purpose
usage descriptions for the permission categories already planned in
`build_permissions.py`, without importing that lab module or its promises of no
recording, fetching, changing, scanning, or sending data. Production descriptions
explain authorized tasks; they are not an implementation of task authorization.
Speech recognition explicitly discloses that audio may be sent to Apple.

This closes the **missing usage metadata** part of the remaining permission gate
in `PRODUCTION-STAGING.md`, not its final-identity grants or runtime gates.
`ServiceHost.swift` remains unchanged: it supervises workers and does not request
consent or implement these data operations. Metadata neither requests nor grants
permissions, adds entitlements, nor proves a worker can use a protected API.

## Apple platform mapping

The links below are Apple's Info.plist key reference pages; their documentation
JSON (`https://developer.apple.com/tutorials/data/documentation/bundleresources/information-property-list/<lowercase-key>.json`)
was checked for platform availability and purpose during this change.
The bundle's existing minimum OS remains macOS 14.0.

| Planned category | Production key / Apple reference | Purpose |
| --- | --- | --- |
| Camera | [NSCameraUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nscamerausagedescription) | Authorized photo/video capture |
| Microphone | [NSMicrophoneUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nsmicrophoneusagedescription) | Authorized audio recording and voice input |
| Contacts | [NSContactsUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nscontactsusagedescription) | Find recipients and manage contacts |
| Calendars | [NSCalendarsFullAccessUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nscalendarsfullaccessusagedescription) | Read availability and manage events; macOS 14+ full access |
| Reminders | [NSRemindersFullAccessUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nsremindersfullaccessusagedescription) | Read/update lists and tasks; macOS 14+ full access |
| Photos | [NSPhotoLibraryUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nsphotolibraryusagedescription) | Read/update photo library, not add-only access |
| Speech | [NSSpeechRecognitionUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nsspeechrecognitionusagedescription) | Transcription, including possible Apple server processing |
| Bluetooth | [NSBluetoothAlwaysUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nsbluetoothalwaysusagedescription) | Communicate with nearby devices; supported on macOS 11+ |
| Location | [NSLocationUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocationusagedescription) | Location-based assistance; Apple's macOS-specific choice |
| Apple Events | [NSAppleEventsUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nsappleeventsusagedescription) | Read information and perform authorized actions in other apps |
| Local Network | [NSLocalNetworkUsageDescription](https://developer.apple.com/documentation/bundleresources/information-property-list/nslocalnetworkusagedescription) | Connect to local devices/services, including direct unicast connections |

Do not copy `NSLocationWhenInUseUsageDescription` from the lab: Apple's reference
explicitly directs macOS apps to `NSLocationUsageDescription` instead. Likewise,
`NSBluetoothPeripheralUsageDescription` is for older iOS deployments, not this
macOS target. Full-access Calendar/Reminders keys match the planned macOS 14+
access; no legacy or write-only keys are added speculatively.

No `NSBonjourServices` is declared: no specific Bonjour registration/browsing is
implemented by this change. Add actual service types only with an implemented,
reviewed discovery feature. [Apple TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)
distinguishes usage descriptions from Bonjour service declarations, dates macOS
Local Network privacy enforcement to macOS 15 (distinct from key availability),
and recommends an Apple-issued code-signing identity for reliable tracking.
An existing signer, association plist, or this metadata does not establish Local
Network authorization or continuity. Location consent for a background host also
remains an explicit live-validation limitation.

Accessibility, Input Monitoring, Screen Recording and Full Disk Access remain
separate permission workflows; this change invents no Info.plist usage keys for
those grants. Do not reset TCC, sample private content, record media, scan devices,
or run permission probes just to validate bundle metadata.

## Evidence-driven limits after the instrumented check

The final-identity Location diagnostic in `PRODUCTION-PERMISSIONS.md` observed an
initial authorization callback and a pumped main-thread run loop, but no grant.
Its worker's own bundle did not expose Verity's metadata. Neither observation
identifies Core Location's responsible client. The frozen native host imports
Foundation, CryptoKit and Darwin and runs `dispatchMain()`; it does not instantiate
or activate NSApplication. This differs from a foreground AppKit consent flow,
but is not by itself proof of the timeout's cause.

Apple's current [authorization overview](https://developer.apple.com/documentation/corelocation/requesting-authorization-to-use-location-services)
recommends checking the manager instance and processing its initial delegate
callback. The [request method](https://developer.apple.com/documentation/corelocation/cllocationmanager/requestwheninuseauthorization())
is available on macOS and documents a foreground requirement. Cross-platform
wording and third-party anecdotes about starting location updates do not establish
that sampling is required here. Do not call `startUpdatingLocation` or
`requestLocation` merely to make this consent test pass.

Current [TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)
explicitly distinguishes launchd **agents** from the daemon exemption, documents
possible Settings ambiguity with multiple app copies (FB15568200), and documents
missing alerts for short-lived failing processes (FB16131937). Neither reported
issue has been isolated in this setup; the observed connection succeeded. It also
requires a unique main-executable UUID for reliable behavior and recommends an
Apple-issued signing identity. Retained signed test bundles and a self-issued
identity must not be silently treated as proof of correct Local Network tracking.

For a future separately scoped connection diagnostic, TN3179 identifies
`NWConnection` waiting state plus `NWPath.UnsatisfiedReason.localNetworkDenied` as
specific denial evidence. It does not offer a general permission-query API, and
a successful connection still does not prove denial enforcement. No network
operation, global preference change, state reset, new user or VM is performed by
this documentary follow-up. The stopped distinct-Verity-row deny/allow boundary
remains in effect.

## Sealing and verification

The builder serializes the canonical dictionary with `plistlib.dumps()` before
compilation/signing. The existing signed bundle and candidate inventory cover
those bytes. `verify_stage()` additionally requires the **exact canonical
Info.plist bytes**, including every identity/version/UI/minimum-OS key and every
usage-description value. A matching inventory and signature do not excuse a
builder that sealed incorrect metadata. Omitted, incorrect, empty or extra fields,
wrong plist types, and noncanonical serialization are rejected. Intentional
metadata changes require a new build and review; older minimal stages fail this
verifier and must not be patched in place after signing.

Compiler isolation, signed service settings, source/runtime selection,
leaf-pinned verification, and atomic success-receipt publication are unchanged.
No success receipt is published if final metadata verification fails. This is
operator-owned staging evidence, not protection against malicious same-user
concurrent writes or an externally trusted deployment receipt.

## Offline regression evidence and remaining gates

Two invariant tests cover presence before signing and rejection of malformed
metadata sealed by the builder itself. Before the fix, the 18-method staging suite
failed with 14 failures: one missing all 11 expected usage descriptions, plus
13 accepted malformed cases (omitted/wrong camera rationale, omitted/wrong five
other bundle fields, and an unplanned Bonjour declaration). Existing identifier
and executable rejection already worked. The final mutation test also covers
empty descriptions and integer `1` substituted for Boolean `LSUIElement`.
The parent replayed the finished two tests against original builder commit
`47831f41be23cf407268226afd133009deeb800b`: 16 failures, zero errors (the initial
14 above plus empty-camera and integer-Boolean cases). On the fixed builder,
parent clean/disposable-state runs passed 65 experiment and 71 controller tests
on Python 3.11; Python 3.14 passed 57 experiment and 71 controller tests, excluding
the eight cryptography-dependent signer tests. Changed-file Ruff/diff checks passed.
Independent metadata review (`deleg_0ef76b0e`, task 1) found no blockers in the
scoped production-purpose, macOS-key, sealed-metadata and preserved-stage-contract
checks. It was source-only, not an independent test or signing run. Parent matched
the reviewed builder/tests to `bf1d45dd0ef4e3f087358018ffa3b6967abc043f` and reverified
the real production-signed stage without installing or executing it.

Run from the repository with Python 3.11 or 3.14, a disposable HOME/HERMES_HOME and
TMPDIR under private scratch, a clean environment, and no credentials:

```sh
"$PYTHON" -B -m unittest discover -s experiments/verity_identity -p test_stage_production_native.py -q
"$PYTHON" -B -m unittest discover -s experiments/verity_identity -p test_controller_lab.py -q
```

These tests use fake compiler/signature adapters and disposable files; they do
not prove real signing, native execution, TCC attribution or protected operations.
Final identity consent, compatible workers, rebuild/rollback continuity, Local
Network/Location behavior, final-path artifact verification and explicit activation
approval remain separate gates. No signing, installation, service selection,
restart, launchd operation or production write is authorized by this document.
