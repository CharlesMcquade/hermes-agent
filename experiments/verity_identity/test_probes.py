"""Portable unit checks: no macOS grants, network operations, or personal data."""

import contextlib
import errno
import io
import json
import unittest
from unittest.mock import MagicMock, patch

import network_probe as network
import permissions_probe as permissions


class ProbeTests(unittest.TestCase):
    def setUp(self):
        permissions.REQUESTED.clear()

    def test_target_validation(self):
        self.assertEqual(
            network.target_from({"address": "10.101.0.2", "port": 80}),
            ("10.101.0.2", 80),
        )
        for ip in ("127.0.0.1", "0.0.0.0", "8.8.8.8", "::1"):
            with self.assertRaises(ValueError):
                network.target_from({"address": ip, "port": 80})
        for port in (0, 65536, True, "80"):
            with self.assertRaises(ValueError):
                network.target_from({"address": "10.1.1.1", "port": port})

    def file_probe(self, error=None):
        output = io.StringIO()
        with (
            patch.object(permissions.os, "open", side_effect=error, return_value=123),
            patch.object(permissions.os, "close"),
            contextlib.redirect_stdout(output),
        ):
            permissions.protected_file("Full Disk Access: Messages", False)
        self.assertNotIn("private", output.getvalue())
        return json.loads(output.getvalue())

    def test_file_open_status(self):
        record = self.file_probe()
        self.assertTrue(record["allowed"])
        self.assertEqual(record["status"], "opened_read_only")

    def test_missing_is_not_denied(self):
        record = self.file_probe(FileNotFoundError("private path"))
        self.assertEqual(record["status"], "missing")
        self.assertIsNone(record["allowed"])

    def test_permission_error_is_denied(self):
        for code, label in ((errno.EPERM, "EPERM"), (errno.EACCES, "EACCES")):
            record = self.file_probe(PermissionError(code, "private path"))
            self.assertFalse(record["allowed"])
            self.assertEqual(record["error_type"], label)

    def test_native_check_never_requests(self):
        ask = MagicMock()
        factory = lambda *_: (lambda: 0, ask, permissions.STANDARD)
        with (
            patch.dict(permissions.FACTORIES, {"Camera": factory}),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            permissions.native("Camera", False)
        ask.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["status"], "not_determined")

    def test_limited_access_stays_distinct(self):
        factory = lambda *_: (
            lambda: 4,
            MagicMock(),
            {**permissions.STANDARD, 4: "limited"},
        )
        with (
            patch.dict(permissions.FACTORIES, {"Photos": factory}),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            permissions.native("Photos", False)
        self.assertEqual(json.loads(out.getvalue())["status"], "limited")

    def test_calendar_write_only_upgrade_and_check_only(self):
        for request in (False, True):
            state = [4]

            def ask():
                state[0] = 3

            mocked = MagicMock(side_effect=ask)
            factory = lambda *_: (
                lambda: state[0],
                mocked,
                {3: "full_access", 4: "write_only"},
            )
            with (
                patch.dict(permissions.FACTORIES, {"Calendar": factory}),
                patch.object(permissions, "wait_for_change", return_value=True),
                contextlib.redirect_stdout(io.StringIO()) as out,
            ):
                permissions.native("Calendar", request)
            self.assertEqual(mocked.call_count, int(request))
            self.assertEqual(
                json.loads(out.getvalue().splitlines()[-1])["status"],
                "full_access" if request else "write_only",
            )

    def test_protected_open_does_not_read(self):
        with (
            patch.object(permissions.os, "open", return_value=123) as opened,
            patch.object(permissions.os, "close") as closed,
            patch.object(
                permissions.os, "read", side_effect=AssertionError("No reads")
            ),
            patch.object(
                permissions.Path,
                "open",
                side_effect=AssertionError("No buffered reads"),
            ),
            contextlib.redirect_stdout(io.StringIO()) as out,
        ):
            permissions.protected_file("Full Disk Access: Messages", False)
        opened.assert_called_once()
        closed.assert_called_once_with(123)
        self.assertEqual(json.loads(out.getvalue())["status"], "opened_read_only")

    def test_special_purpose_target_rejected(self):
        for ip in ("192.0.2.1", "198.18.0.1", "169.254.1.1", "240.0.0.1"):
            with self.assertRaises(ValueError):
                network.target_from({"address": ip, "port": 80})

    def test_on_link_is_not_merely_private(self):
        direct = "flags: <UP,HOST,DONE,LLINFO>\ninterface: en0"
        self.assertEqual(
            network.validate_link("10.1.1.2", direct, "10.1.1.3", "255.255.255.0"),
            "en0",
        )
        for address, route in (
            ("10.2.1.2", direct),
            ("10.1.1.2", "flags: <UP,GATEWAY>\ninterface: en0"),
            ("10.1.1.2", "flags: <UP>\ninterface: utun0"),
            ("10.1.1.255", direct),
        ):
            with self.assertRaises(ValueError):
                network.validate_link(address, route, "10.1.1.3", "255.255.255.0")

    def supervise_fixture(self, body, on_event=None):
        import subprocess
        import sys
        from pathlib import Path

        popen = subprocess.Popen
        children, records = [], []
        code = (
            "import sys,time; sys.path.insert(0, "
            + repr(str(Path(permissions.__file__).parent))
            + "); import permissions_probe as p; "
            + body
        )

        def spawn(_argv, **kwargs):
            child = popen([sys.executable, "-u", "-c", code], **kwargs)
            children.append(child)
            return child

        def emit(event, **values):
            records.append(dict(event=event, **values))
            if on_event:
                on_event(event, values, children)

        with (
            patch.object(permissions.subprocess, "Popen", side_effect=spawn),
            patch.object(permissions, "NAMES", ("Camera",)),
            patch.object(permissions, "CHECK_TIMEOUT", 0.5),
            patch.object(permissions, "emit", side_effect=emit),
        ):
            try:
                result = permissions.supervise("permissions-check", "unused")
            finally:
                permissions.cleanup()
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertFalse(permissions.ACTIVE)
        return result, records

    def test_progress_forwarded_before_worker_exit(self):
        observed = []

        def on_event(event, values, children):
            if event == "permission" and values["status"] == "requesting":
                observed.append(children[0].poll() is None)

        result, _ = self.supervise_fixture(
            "p.permission('Camera','requesting',None,True); time.sleep(60)", on_event
        )
        self.assertEqual(observed, [True])
        self.assertEqual(result, 1)

    def test_worker_crash_is_failure_even_after_result(self):
        result, records = self.supervise_fixture(
            "p.permission('Camera','authorized',True); sys.exit(11)"
        )
        self.assertEqual(result, 1)
        self.assertEqual(records[-1]["error_type"], "WorkerCrash")

    def test_worker_protocol_does_not_leak_stdout(self):
        result, records = self.supervise_fixture("print('private sentinel',flush=True)")
        self.assertEqual(result, 1)
        self.assertNotIn("private sentinel", json.dumps(records))
        self.assertTrue(
            any(r.get("error_type") == "WorkerProtocolError" for r in records)
        )


if __name__ == "__main__":
    unittest.main()
