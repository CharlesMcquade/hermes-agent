"""Isolated consent/status probe; never import Hermes or return private content.

Usage: python -S -s -P -u permissions_probe.py MODE BRIDGE
MODE: permissions-check (no consent requests) or permissions-request.
--worker NAME is internal. Workers retain sys.executable and the entire inherited
process environment, including PYTHONHOME. Supply a bridge matching Python's ABI.

A successful check means the API ran, NOT that access was granted. Limited Photos
or Contacts access is labeled limited; Calendar write-only is not full access.
FDA results apply only to the two tested files, not all protected locations.
Hermes-launched checks inherit its grants and are helper smoke tests, not evidence
of signed-host attribution. Request paths require suitable host usage strings.
"""

import argparse
import ctypes as C
import errno
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


ACTIVE = {}
REQUESTED = set()
CHECK_TIMEOUT = 20
REQUEST_TIMEOUT = 450
MAX_WORKERS = 12
STANDARD = {0: "not_determined", 1: "restricted", 2: "denied", 3: "authorized"}
NATIVE_NAMES = (
    "Contacts",
    "Calendar",
    "Reminders",
    "Camera",
    "Microphone",
    "Photos",
    "Speech",
    "Bluetooth",
    "Location",
)
FILE_PATHS = {
    "Full Disk Access: Messages": "Library/Messages/chat.db",
    "Full Disk Access: Safari": "Library/Safari/History.db",
}
NAMES = (
    *FILE_PATHS,
    "Accessibility",
    "Input Monitoring",
    "Screen Capture",
    *NATIVE_NAMES,
)


def emit(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)


def permission(name, status, allowed=None, requested=False, error_type=None):
    if requested:
        REQUESTED.add(name)
    emit(
        "permission",
        name=name,
        status=status,
        allowed=allowed,
        requested=requested or name in REQUESTED,
        error_type=error_type,
    )


def wait_for_change(status, before, done=None):
    import Foundation as F

    deadline = time.monotonic() + REQUEST_TIMEOUT - 5
    while status() == before and not (done and done[0]):
        if time.monotonic() >= deadline:
            return False
        F.NSRunLoop.currentRunLoop().runUntilDate_(
            F.NSDate.dateWithTimeIntervalSinceNow_(0.1)
        )
    return True


def protected_file(name, request):
    del request  # No programmatic FDA request exists.
    try:
        fd = os.open(Path.home() / FILE_PATHS[name], os.O_RDONLY)
        os.close(fd)  # Prove read-open authorization without fetching any bytes.
        permission(name, "opened_read_only", True)
    except FileNotFoundError:
        permission(name, "missing", error_type="FileNotFoundError")
    except OSError as exc:
        labels = {errno.EPERM: "EPERM", errno.EACCES: "EACCES"}
        if exc.errno not in labels:
            raise
        permission(name, "denied", False, error_type=labels[exc.errno])


def framework(name):
    return C.CDLL("/System/Library/Frameworks/" + name + ".framework/" + name)


def boolean_function(lib, name):
    fn = getattr(lib, name)
    fn.argtypes = []
    fn.restype = C.c_bool
    return fn


def accessibility(name, request):
    lib = framework("ApplicationServices")
    cf = framework("CoreFoundation")
    trusted = boolean_function(lib, "AXIsProcessTrusted")
    before = bool(trusted())
    requested = request and not before
    if requested:
        keys = (C.c_void_p * 1)(
            C.c_void_p.in_dll(lib, "kAXTrustedCheckOptionPrompt").value
        )
        values = (C.c_void_p * 1)(C.c_void_p.in_dll(cf, "kCFBooleanTrue").value)
        cf.CFDictionaryCreate.argtypes = [
            C.c_void_p,
            C.POINTER(C.c_void_p),
            C.POINTER(C.c_void_p),
            C.c_long,
            C.c_void_p,
            C.c_void_p,
        ]
        cf.CFDictionaryCreate.restype = C.c_void_p
        cf.CFRelease.argtypes = [C.c_void_p]
        cf.CFRelease.restype = None
        options = cf.CFDictionaryCreate(None, keys, values, 1, None, None)
        lib.AXIsProcessTrustedWithOptions.argtypes = [C.c_void_p]
        lib.AXIsProcessTrustedWithOptions.restype = C.c_bool
        permission(name, "requesting", before, True)
        try:
            lib.AXIsProcessTrustedWithOptions(options)
        finally:
            cf.CFRelease(options)
        completed = wait_for_change(trusted, False)
    else:
        completed = True
    allowed = bool(trusted())
    permission(
        name,
        "authorized" if allowed else "not_authorized",
        allowed,
        requested,
        None if completed else "ConsentTimeout",
    )
    # Copy only the focused application AX handle. Never read titles/private text.
    lib.AXUIElementCreateSystemWide.argtypes = []
    lib.AXUIElementCreateSystemWide.restype = C.c_void_p
    lib.AXUIElementCopyAttributeValue.argtypes = [
        C.c_void_p,
        C.c_void_p,
        C.POINTER(C.c_void_p),
    ]
    lib.AXUIElementCopyAttributeValue.restype = C.c_int32
    cf.CFStringCreateWithCString.argtypes = [C.c_void_p, C.c_char_p, C.c_uint32]
    cf.CFStringCreateWithCString.restype = C.c_void_p
    cf.CFRelease.argtypes = [C.c_void_p]
    cf.CFRelease.restype = None
    element = lib.AXUIElementCreateSystemWide()
    attribute = cf.CFStringCreateWithCString(None, b"AXFocusedApplication", 0x08000100)
    value = C.c_void_p()
    try:
        result = lib.AXUIElementCopyAttributeValue(element, attribute, C.byref(value))
        permission("Accessibility operation", int(result), result == 0)
    finally:
        for handle in (value.value, attribute, element):
            if handle:
                cf.CFRelease(handle)

    # System-wide focused-app lookup can fail independently of authorization.
    # Read a fixed installed app's AX role too; do not read window titles/text.
    from AppKit import NSRunningApplication

    apps = NSRunningApplication.runningApplicationsWithBundleIdentifier_(
        "com.apple.finder"
    )
    if not apps:
        permission("Accessibility Finder role", "target_not_running")
        return
    lib.AXUIElementCreateApplication.argtypes = [C.c_int32]
    lib.AXUIElementCreateApplication.restype = C.c_void_p
    element = lib.AXUIElementCreateApplication(apps[0].processIdentifier())
    attribute = cf.CFStringCreateWithCString(None, b"AXRole", 0x08000100)
    value = C.c_void_p()
    try:
        result = lib.AXUIElementCopyAttributeValue(element, attribute, C.byref(value))
        permission(
            "Accessibility Finder role", int(result), result == 0 and bool(value.value)
        )
    finally:
        for handle in (value.value, attribute, element):
            if handle:
                cf.CFRelease(handle)


def preflight(name, request):
    lib = framework("CoreGraphics")
    suffix = {
        "Input Monitoring": "ListenEventAccess",
        "Screen Capture": "ScreenCaptureAccess",
    }[name]
    status = boolean_function(lib, "CGPreflight" + suffix)
    before = bool(status())
    requested = request and not before
    completed = True
    if requested:
        permission(name, "requesting", before, True)
        boolean_function(lib, "CGRequest" + suffix)()
        completed = wait_for_change(status, False)
    allowed = bool(status())
    permission(
        name,
        "authorized" if allowed else "not_authorized",
        allowed,
        requested,
        None if completed else "ConsentTimeout",
    )


def contacts(callback, keep):
    import Contacts as M

    def ask():
        obj = M.CNContactStore.alloc().init()
        keep.append(obj)
        obj.requestAccessForEntityType_completionHandler_(
            M.CNEntityTypeContacts, callback
        )

    return (
        lambda: M.CNContactStore.authorizationStatusForEntityType_(
            M.CNEntityTypeContacts
        ),
        ask,
        {**STANDARD, 4: "limited"},
    )


def eventkit(callback, keep, reminders=False):
    import EventKit as M

    entity = M.EKEntityTypeReminder if reminders else M.EKEntityTypeEvent

    def ask():
        obj = M.EKEventStore.alloc().init()
        keep.append(obj)
        if reminders:
            obj.requestFullAccessToRemindersWithCompletion_(callback)
        else:
            obj.requestFullAccessToEventsWithCompletion_(callback)

    return (
        lambda: M.EKEventStore.authorizationStatusForEntityType_(entity),
        ask,
        {**STANDARD, 3: "full_access", 4: "write_only"},
    )


def avfoundation(callback, keep, microphone=False):
    import AVFoundation as M

    media = M.AVMediaTypeAudio if microphone else M.AVMediaTypeVideo
    return (
        lambda: M.AVCaptureDevice.authorizationStatusForMediaType_(media),
        lambda: M.AVCaptureDevice.requestAccessForMediaType_completionHandler_(
            media, callback
        ),
        STANDARD,
    )


def photos(callback, keep):
    import Photos as M

    level = M.PHAccessLevelReadWrite
    return (
        lambda: M.PHPhotoLibrary.authorizationStatusForAccessLevel_(level),
        lambda: M.PHPhotoLibrary.requestAuthorizationForAccessLevel_handler_(
            level, callback
        ),
        {**STANDARD, 4: "limited"},
    )


def speech(callback, keep):
    import Speech as M

    return (
        M.SFSpeechRecognizer.authorizationStatus,
        lambda: M.SFSpeechRecognizer.requestAuthorization_(callback),
        {0: "not_determined", 1: "denied", 2: "restricted", 3: "authorized"},
    )


def bluetooth(callback, keep):
    import Foundation as F
    import CoreBluetooth as M

    class BluetoothConsentDelegate(F.NSObject):
        def centralManagerDidUpdateState_(self, manager):
            if int(M.CBManager.authorization()) != 0:
                callback()

    def ask():
        delegate = BluetoothConsentDelegate.alloc().init()
        keep.append(delegate)
        # Initialization only. No scanning, discovery, or connections.
        keep.append(
            M.CBCentralManager.alloc().initWithDelegate_queue_options_(
                delegate, None, None
            )
        )

    return M.CBManager.authorization, ask, STANDARD


def location(callback, keep):
    import Foundation as F
    import CoreLocation as M

    if not M.CLLocationManager.locationServicesEnabled():
        return lambda: -1, lambda: None, {-1: "services_disabled"}

    class LocationConsentDelegate(F.NSObject):
        def locationManagerDidChangeAuthorization_(self, manager):
            if int(manager.authorizationStatus()) != 0:
                callback()

    # Class status query in check mode avoids creating a manager/delegate.
    def ask():
        delegate = LocationConsentDelegate.alloc().init()
        obj = M.CLLocationManager.alloc().init()
        obj.setDelegate_(delegate)
        keep.extend([delegate, obj])
        obj.requestWhenInUseAuthorization()

    return (
        M.CLLocationManager.authorizationStatus,
        ask,
        {**STANDARD, 3: "authorized_always", 4: "authorized_when_in_use"},
    )


FACTORIES = {
    "Contacts": contacts,
    "Calendar": eventkit,
    "Reminders": lambda cb, keep: eventkit(cb, keep, True),
    "Camera": avfoundation,
    "Microphone": lambda cb, keep: avfoundation(cb, keep, True),
    "Photos": photos,
    "Speech": speech,
    "Bluetooth": bluetooth,
    "Location": location,
}


def native(name, request):
    done, keep = [False], []

    def callback(*args):
        # Never stringify callback objects (NSError descriptions may contain data).
        done[0] = True

    status, ask, labels = FACTORIES[name](callback, keep)
    before = int(status())
    requested = request and (before == 0 or (name == "Calendar" and before == 4))
    completed = True
    if requested:
        permission(name, "requesting", None, True)
        ask()
        completed = wait_for_change(status, before, done)
    after = int(status())
    label = labels.get(after, "unknown")
    allowed = (
        None
        if label in ("not_determined", "unknown")
        else label
        in (
            "authorized",
            "full_access",
            "limited",
            "authorized_always",
            "authorized_when_in_use",
        )
    )
    permission(name, label, allowed, requested, None if completed else "ConsentTimeout")


def run_worker(name, request):
    handlers = {
        **dict.fromkeys(FILE_PATHS, protected_file),
        "Accessibility": accessibility,
        "Input Monitoring": preflight,
        "Screen Capture": preflight,
        **dict.fromkeys(NATIVE_NAMES, native),
    }
    try:
        handlers[name](name, request)
        return 0
    except Exception as exc:
        permission(name, "error", error_type=type(exc).__name__)
        return 1


def cleanup():
    children = list(ACTIVE)
    for child in children:
        if child.poll() is None:
            child.terminate()
    deadline = time.monotonic() + 2
    for child in children:
        try:
            child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        child.stdout.close()
        ACTIVE.pop(child, None)


def interrupted(signum, frame):
    raise SystemExit(128 + signum)


def forward_line(line, state):
    # Validate before forwarding; arbitrary worker stdout is never printed.
    name = state["name"]
    try:
        item = json.loads(line)
        if (
            item.get("event") != "permission"
            or item.get("name")
            not in (name, "Accessibility operation", "Accessibility Finder role")
            or set(item)
            != {"event", "name", "status", "allowed", "requested", "error_type"}
            or type(item["requested"]) is not bool
            or (item["allowed"] is not None and type(item["allowed"]) is not bool)
        ):
            raise ValueError()
        if item["requested"]:
            REQUESTED.add(name)
        emit(**item)
        state["found"] |= item["status"] != "requesting"
    except (ValueError, TypeError, AttributeError):
        permission(name, "error", error_type="WorkerProtocolError")
        state["failed"] = 1


def drain(child, state, final=False):
    # Nonblocking reads expose requesting events while consent is still pending.
    while True:
        try:
            chunk = os.read(child.stdout.fileno(), 8192)
        except BlockingIOError:
            break
        if not chunk:
            break
        state["buffer"] += chunk
        while b"\n" in state["buffer"]:
            line, state["buffer"] = state["buffer"].split(b"\n", 1)
            forward_line(line, state)
        if len(state["buffer"]) > 8192:
            permission(state["name"], "error", error_type="WorkerProtocolError")
            state["failed"] = 1
            state["buffer"] = b""
    if final and state["buffer"]:
        forward_line(state["buffer"], state)
        state["buffer"] = b""
    if final and (child.returncode or not state["found"]):
        permission(
            state["name"],
            "error",
            error_type="WorkerCrash" if child.returncode else "WorkerNoResult",
        )
        state["failed"] = 1


def supervise(mode, bridge):
    pending = list(NAMES)
    timeout = REQUEST_TIMEOUT if mode == "permissions-request" else CHECK_TIMEOUT
    failed = 0
    while pending or ACTIVE:
        while pending and len(ACTIVE) < MAX_WORKERS:
            name = pending.pop(0)
            # Close the signal/Popen-registration race; children inherit an
            # unblocked mask via restore in their own entry point.
            oldmask = signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
            )
            try:
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-S",
                        "-s",
                        "-P",
                        "-u",
                        str(Path(__file__).absolute()),
                        mode,
                        bridge,
                        "--worker",
                        name,
                    ],
                    env=os.environ.copy(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=False,
                )
                ACTIVE[child] = dict(
                    name=name,
                    started=time.monotonic(),
                    buffer=b"",
                    found=False,
                    failed=0,
                )
                os.set_blocking(child.stdout.fileno(), False)
                emit("worker-start", name=name, pid=child.pid, ppid=os.getpid())
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, oldmask)
        for child, state in list(ACTIVE.items()):
            drain(child, state)
            if child.poll() is None and time.monotonic() - state["started"] >= timeout:
                child.kill()
                child.wait()
                permission(state["name"], "timeout", error_type="WorkerTimeout")
                state["failed"] = 1
            if child.poll() is not None:
                drain(child, state, final=True)
                failed |= state["failed"]
                child.stdout.close()
                del ACTIVE[child]
        if ACTIVE:
            select.select([c.stdout for c in ACTIVE], [], [], 0.02)
    return failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=("permissions-check", "permissions-request", "permissions-sleep"),
    )
    parser.add_argument("bridge")
    parser.add_argument("--worker", choices=NAMES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    sys.path.insert(0, args.bridge)
    sys.dont_write_bytecode = True
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    if args.worker and args.mode == "permissions-sleep":
        time.sleep(60)  # Controlled blocked-worker cleanup test, no permission APIs.
        return 0
    if args.worker:
        return run_worker(args.worker, args.mode == "permissions-request")
    emit(
        "python-start",
        pid=os.getpid(),
        ppid=os.getppid(),
        executable=sys.executable,
        version=sys.version.split()[0],
    )
    result = 1
    try:
        result = supervise(args.mode, args.bridge)
    except SystemExit as exc:
        result = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:
        permission("Supervisor", "error", error_type=type(exc).__name__)
    finally:
        # Ignore repeated interrupts while reaping our own children.
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        cleanup()
        emit("probe-complete", exit_code=result)
    return result


if __name__ == "__main__":
    sys.exit(main())
