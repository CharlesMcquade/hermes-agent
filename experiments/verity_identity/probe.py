"""Fixed read-only probes. No media capture, app data output, or Hermes imports."""
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def emit(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)


def automation(request):
    class Desc(C.Structure):
        _fields_ = [("kind", C.c_uint32), ("handle", C.c_void_p)]

    lib = C.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
    lib.AECreateDesc.argtypes = [C.c_uint32, C.c_void_p, C.c_long, C.POINTER(Desc)]
    lib.AECreateDesc.restype = C.c_int32
    lib.AEDeterminePermissionToAutomateTarget.argtypes = [C.POINTER(Desc), C.c_uint32, C.c_uint32, C.c_bool]
    lib.AEDeterminePermissionToAutomateTarget.restype = C.c_int32
    lib.AEDisposeDesc.argtypes = [C.POINTER(Desc)]
    four = lambda s: int.from_bytes(s.encode(), "big")
    raw, desc = b"com.apple.finder", Desc()
    created = lib.AECreateDesc(four("bund"), raw, len(raw), C.byref(desc))
    if created:
        raise RuntimeError("AECreateDesc failed")
    try:
        status = lib.AEDeterminePermissionToAutomateTarget(C.byref(desc), four("core"), four("getd"), request)
    finally:
        lib.AEDisposeDesc(C.byref(desc))
    emit("finder-authorization", status=status, requested=request)
    if status == 0:
        # Unlike `get version`, this exercises a protected Apple Event.
        result = subprocess.run(["/usr/bin/osascript", "-e", 'tell application "Finder" to count windows'],
                                capture_output=True, timeout=12)
        emit("finder-operation", exit_code=result.returncode, output_discarded=True)


def main():
    mode, bridge = sys.argv[1:]
    emit("python-start", pid=os.getpid(), ppid=os.getppid(), executable=str(Path(sys.executable).resolve()),
         version=sys.version.split()[0], env_keys=sorted(os.environ))
    if mode == "fail":
        sys.exit(23)
    if mode == "sleep":
        time.sleep(120)
        return
    lib = C.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
    lib.AXIsProcessTrusted.restype = C.c_bool
    cg = C.CDLL("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
    cg.CGPreflightScreenCaptureAccess.restype = C.c_bool
    cg.CGPreflightListenEventAccess.restype = C.c_bool
    emit("child-preflight", accessibility=bool(lib.AXIsProcessTrusted()),
         screen=bool(cg.CGPreflightScreenCaptureAccess()), input_monitoring=bool(cg.CGPreflightListenEventAccess()))
    try:
        with (Path.home() / "Library/Messages/chat.db").open("rb") as stream:
            stream.read(1)
        emit("protected-open", readable=True, content_discarded=True)
    except OSError as exc:
        emit("protected-open", readable=False, error=type(exc).__name__, errno=exc.errno)
    sys.path.insert(0, bridge)
    try:
        import AVFoundation as av
        emit("child-camera", status=int(av.AVCaptureDevice.authorizationStatusForMediaType_(av.AVMediaTypeVideo)))
    except ImportError as exc:
        emit("child-camera", error=type(exc).__name__)
    automation(mode == "request-finder")
    emit("probe-complete")


if __name__ == "__main__":
    main()
