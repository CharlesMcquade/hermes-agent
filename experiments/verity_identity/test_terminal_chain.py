"""Evidence checker and SSE framing regressions; no permissions or network calls."""

import copy
import errno
import io
import json
import unittest

from verify_terminal_chain import TerminalStream, check_result


def evidence(bare):
    return [
        {"event": "chain-complete", "exit_code": 0},
        {"event": "network-control", "errno": errno.EPERM},
        *[
            {
                "event": "permission",
                "name": name,
                "allowed": not bare,
                "requested": False,
                "status": status if not bare else "denied",
            }
            for name, status in (
                ("Full Disk Access: Messages", "opened_read_only"),
                ("Full Disk Access: Safari", "opened_read_only"),
                ("Accessibility", "authorized"),
                ("Accessibility Finder role", 0),
            )
        ],
    ]


class EvidenceTests(unittest.TestCase):
    def test_required_checks_cannot_be_missing_denied_or_requested(self):
        for bare in (False, True):
            good = evidence(bare)
            check_result(good, bare)
            wrong_allowed = copy.deepcopy(good)
            wrong_allowed[2]["allowed"] = bare
            requested = copy.deepcopy(good)
            requested[2]["requested"] = True
            wrong_status = copy.deepcopy(good)
            wrong_status[2]["status"] = "missing"
            for broken in (
                good[1:],
                good[:1] + good[2:],
                good[:-1],
                good + [good[-1]],
                wrong_allowed,
                requested,
                wrong_status,
            ):
                with (
                    self.subTest(bare=bare, broken=broken),
                    self.assertRaises(AssertionError),
                ):
                    check_result(broken, bare)

    def test_pty_chunks_are_reassembled_before_json_validation(self):
        text = (
            "command echo\r\n"
            + "\r\n".join(map(json.dumps, evidence(False)))
            + "\r\nVERITY_STATUS:0\r\n"
        )
        chunks = [text[i : i + 17] for i in range(0, len(text), 17)]
        wire = "".join(
            "event: output\ndata: " + json.dumps({"text": chunk}) + "\n\n"
            for chunk in chunks
        )
        stream = TerminalStream(io.BytesIO(wire.encode()))
        stream.thread.join(2)
        self.assertFalse(stream.thread.is_alive())
        self.assertFalse(stream.errors)
        self.assertEqual(stream.records(), evidence(False))
        check_result(stream.records(), False)


if __name__ == "__main__":
    unittest.main()
