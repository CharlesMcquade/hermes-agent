"""Fail-closed macOS native host identity, without psutil or environment export.

Process records: pid, ppid, uid, executable (proc_pidpath), argv (exact
KERN_PROCARGS2 arguments only), start_time (kernel epoch seconds, microseconds).
The controller's Host methods are the injection boundary for offline tests.
"""

import ctypes as C
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re


def require(condition, message):
    from restart_production import require as check

    check(condition, message)


def contract(manifest):
    native = manifest["native_host"]
    require(
        isinstance(native, dict)
        and set(native)
        == {
            "bundle",
            "executable",
            "bundle_id",
            "requirement",
            "inventory",
            "launcher_sha256",
        },
        "Invalid native_host schema",
    )
    for key in ("bundle", "executable"):
        value = native[key]
        require(
            isinstance(value, str)
            and "\x00" not in value
            and Path(value).is_absolute(),
            "Invalid native host path",
        )
    require(
        native["executable"]
        == str(Path(native["bundle"]) / "Contents/MacOS/VerityServiceHost"),
        "Native executable must be inside bundle",
    )
    identifier = native["bundle_id"]
    require(
        isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", identifier),
        "Invalid native bundle identifier",
    )
    # A narrow conjunction prevents an OR/identifier-only requirement bypass.
    require(
        isinstance(native["requirement"], str)
        and re.fullmatch(
            r'identifier "'
            + re.escape(identifier)
            + r'" and certificate leaf = H"[0-9a-fA-F]{40}"',
            native["requirement"],
        ),
        "Native requirement must pin identifier and certificate leaf hash",
    )
    require(
        isinstance(native["inventory"], dict) and native["inventory"],
        "Missing native inventory",
    )
    require(
        isinstance(native["launcher_sha256"], str)
        and re.fullmatch("[0-9a-f]{64}", native["launcher_sha256"]),
        "Invalid launcher hash",
    )
    return native


def bootstrap_environment(settings):
    """Resolve only the signed allowlist; never inherit controller environment."""
    defaults = {
        "HOME": settings["base"] + "/home",
        "TMPDIR": settings["base"] + "/tmp",
        "HERMES_HOME": settings["base"] + "/state",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if "bootstrap_environment" not in settings:
        return defaults
    env = settings["bootstrap_environment"]
    require(
        isinstance(env, dict) and set(env) == set(defaults),
        "Invalid signed bootstrap environment keys",
    )
    require(
        all(isinstance(value, str) and "\u0000" not in value for value in env.values()),
        "Invalid signed bootstrap environment values",
    )
    require(
        all(env[key].startswith("/") for key in ("HOME", "TMPDIR", "HERMES_HOME"))
        and all(
            env[key] == defaults[key]
            for key in ("PATH", "PYTHONNOUSERSITE", "PYTHONDONTWRITEBYTECODE")
        ),
        "Invalid signed bootstrap environment policy",
    )
    return dict(env)


def validate_bundle(manifest, base, host):
    from production_launcher import inventory

    native = contract(manifest)
    app = Path(native["bundle"])
    require(not app.is_symlink() and app.is_dir(), "Unavailable native bundle")
    require(inventory(app) == native["inventory"], "Native bundle inventory mismatch")
    require(
        host.verify_native_bundle(str(app), native["requirement"]),
        "Native bundle signature invalid",
    )
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    require(
        info.get("CFBundleIdentifier") == native["bundle_id"],
        "Native bundle identifier mismatch",
    )
    settings = json.loads(
        (app / "Contents/Resources/service-settings.json").read_text()
    )
    launcher = str(Path(base) / "production_launcher.py")
    require(
        manifest.get("launcher_path", launcher) == launcher,
        "Native launcher path mismatch",
    )
    require(
        isinstance(settings, dict)
        and set(settings)
        in (
            {"base", "bootstrap_python", "launcher", "launcher_sha256", "roles"},
            {
                "base",
                "bootstrap_python",
                "launcher",
                "launcher_sha256",
                "roles",
                "bootstrap_environment",
            },
        ),
        "Invalid signed settings",
    )
    require(
        settings["base"] == str(base)
        and settings["launcher"] == launcher
        and settings["launcher_sha256"] == native["launcher_sha256"]
        and settings["roles"] == ["agent", "webui"],
        "Native signed settings mismatch",
    )
    bootstrap_environment(settings)
    python = settings["bootstrap_python"]
    require(
        isinstance(python, str)
        and Path(python).is_absolute()
        and Path(python).is_file()
        and os.access(python, os.X_OK),
        "Invalid native bootstrap Python",
    )
    require(
        hashlib.sha256(Path(launcher).read_bytes()).hexdigest()
        == native["launcher_sha256"],
        "Native launcher hash mismatch",
    )
    require(
        inventory(app) == native["inventory"], "Native bundle changed during inspection"
    )


class BSDInfo(C.Structure):
    _fields_ = [
        (name, C.c_uint32)
        for name in (
            "flags",
            "status",
            "xstatus",
            "pid",
            "ppid",
            "uid",
            "gid",
            "ruid",
            "rgid",
            "svuid",
            "svgid",
            "rfu",
        )
    ]
    _fields_ += [("comm", C.c_char * 16), ("name", C.c_char * 32)]
    _fields_ += [
        (name, C.c_uint32)
        for name in ("nfiles", "pgid", "pjobc", "e_tdev", "e_tpgid", "nice")
    ]
    _fields_ += [("start_sec", C.c_uint64), ("start_usec", C.c_uint64)]


def process_identity(pid):
    require(type(pid) is int and pid > 1, "Invalid process PID")
    lib = C.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    lib.proc_pidinfo.argtypes = [C.c_int, C.c_int, C.c_uint64, C.c_void_p, C.c_int]
    lib.proc_pidpath.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
    info = BSDInfo()
    require(
        lib.proc_pidinfo(pid, 3, 0, C.byref(info), C.sizeof(info)) == C.sizeof(info),
        "Cannot read process birth/ownership",
    )
    path = C.create_string_buffer(4096)
    require(
        lib.proc_pidpath(pid, path, len(path)) > 0, "Cannot read process executable"
    )
    libc = C.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.sysctl.argtypes = [
        C.POINTER(C.c_int),
        C.c_uint,
        C.c_void_p,
        C.POINTER(C.c_size_t),
        C.c_void_p,
        C.c_size_t,
    ]
    mib = (C.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
    size = C.c_size_t(1024 * 1024)
    buf = C.create_string_buffer(size.value)
    require(
        libc.sysctl(mib, 3, buf, C.byref(size), None, 0) == 0,
        "Cannot read process arguments",
    )
    raw = buf.raw[: size.value]
    argc = C.c_int.from_buffer_copy(raw[:4]).value
    require(0 < argc < 65536, "Invalid process argc")
    end = raw.find(b"\0", 4)
    require(end >= 4, "Malformed process argument header")
    pos = end + 1
    while pos < len(raw) and raw[pos] == 0:
        pos += 1
    argv = []
    for _ in range(argc):
        end = raw.find(b"\0", pos)
        require(end >= pos, "Truncated process arguments")
        argv.append(os.fsdecode(raw[pos:end]))
        pos = end + 1
    # Never decode or expose the remaining environment bytes.
    return dict(
        pid=int(info.pid),
        ppid=int(info.ppid),
        uid=int(info.uid),
        executable=os.fsdecode(path.value),
        argv=argv,
        start_time=info.start_sec + info.start_usec / 1000000,
    )


def verify_signature(pid, requirement):
    """Validate the running guest, not just an on-disk lookalike."""
    cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    sec = C.CDLL("/System/Library/Frameworks/Security.framework/Security")
    ptr = C.c_void_p

    def bind(lib, name, args, result):
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, result
        return fn

    string = bind(cf, "CFStringCreateWithCString", [ptr, C.c_char_p, C.c_uint32], ptr)
    number = bind(cf, "CFNumberCreate", [ptr, C.c_int, ptr], ptr)
    dictionary = bind(
        cf, "CFDictionaryCreate", [ptr, ptr, ptr, C.c_long, ptr, ptr], ptr
    )
    release = bind(cf, "CFRelease", [ptr], None)
    req_create = bind(
        sec,
        "SecRequirementCreateWithString",
        [ptr, C.c_uint32, C.POINTER(ptr)],
        C.c_int32,
    )
    guest = bind(
        sec,
        "SecCodeCopyGuestWithAttributes",
        [ptr, ptr, C.c_uint32, C.POINTER(ptr)],
        C.c_int32,
    )
    check = bind(sec, "SecCodeCheckValidity", [ptr, C.c_uint32, ptr], C.c_int32)
    owned = []
    try:
        text = string(None, requirement.encode(), 0x08000100)
        require(text, "Cannot create code requirement string")
        owned.append(text)
        req = ptr()
        require(req_create(text, 0, C.byref(req)) == 0, "Invalid code requirement")
        owned.append(req)
        value = C.c_int(pid)
        num = number(None, 9, C.byref(value))  # kCFNumberIntType
        require(num, "Cannot create guest PID")
        owned.append(num)
        key = ptr.in_dll(sec, "kSecGuestAttributePid")
        keys, values = (ptr * 1)(key.value), (ptr * 1)(num)
        attrs = dictionary(None, keys, values, 1, None, None)
        require(attrs, "Cannot create guest attributes")
        owned.append(attrs)
        code = ptr()
        require(
            guest(None, attrs, 0, C.byref(code)) == 0,
            "Cannot resolve running native code",
        )
        owned.append(code)
        return check(code, 0, req) == 0  # Dynamic validation; disk preflight is strict.
    finally:
        for obj in reversed(owned):
            release(obj)


def pair(manifest, service, parent_pid, child_pid, host, now, since=None):
    native = contract(manifest)
    parent = host.process_identity(parent_pid)
    child = host.process_identity(child_pid)
    for record, pid in ((parent, parent_pid), (child, child_pid)):
        require(
            record["pid"] == pid and record["uid"] == os.getuid(),
            "Native process PID/UID mismatch",
        )
        birth = record["start_time"]
        require(
            type(birth) in (int, float)
            and math.isfinite(birth)
            and 0 < birth <= now + 5,
            "Invalid native process birth",
        )
        if since is not None:
            require(birth >= since, "Native process predates restart")
    require(
        parent["ppid"] == 1
        and parent["argv"] == [native["executable"], service]
        and parent["executable"] == str(Path(native["executable"]).resolve()),
        "Native host role/executable mismatch",
    )
    argv = manifest["services"][service]["argv"]
    require(
        child["ppid"] == parent_pid and child["pid"] != parent_pid,
        "Native child is not direct host child",
    )
    require(child["start_time"] >= parent["start_time"], "Native child predates host")
    require(
        child["argv"] == argv and child["executable"] == str(Path(argv[0]).resolve()),
        "Native child runtime/argv mismatch",
    )
    require(
        host.verify_native_signature(parent_pid, native["requirement"]),
        "Running native signature invalid",
    )
    return {"host": parent, "child": child}


def unchanged(identity, host):
    for role in identity.values():
        for record in role.values():
            require(
                host.process_identity(record["pid"]) == record,
                "Native process changed during inspection",
            )
