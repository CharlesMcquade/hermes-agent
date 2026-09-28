"""Check-only service-role continuity with exact original lab restoration."""

import argparse
import json
from pathlib import Path

from combined_lab import Lab
from verify_permissions_live import EXPECTED


def check(result):
    permissions = {
        e["name"]: e for e in result["events"] if e.get("event") == "permission"
    }
    assert set(EXPECTED) <= set(permissions)
    assert all(not p["requested"] for p in permissions.values())
    if result["bare"]:
        assert all(permissions[n]["allowed"] is not True for n in EXPECTED)
    else:
        assert all(
            permissions[n]["allowed"] is True and permissions[n]["status"] == s
            for n, s in EXPECTED.items()
        ), {
            n: permissions[n]["status"]
            for n, s in EXPECTED.items()
            if permissions[n]["status"] != s
        }
    return permissions


def verify(root):
    lab = Lab(root)
    report = {"status": "running", "cases": []}
    try:
        with lab.installed():
            for role, slot, bare in [
                ("agent", "a", False),
                ("webui", "a", False),
                ("agent", "b", False),
                ("webui", "b", False),
                ("webui", "b", True),
                ("webui", "b", False),
            ]:
                result = lab.permission(role, slot, bare)
                perms = check(result)
                case = {
                    "role": role,
                    "slot": slot,
                    "bare": bare,
                    "passed": True,
                    "output": result["output"],
                    "permissions": perms,
                }
                report["cases"].append(case)
                print(
                    json.dumps({k: v for k, v in case.items() if k != "permissions"}),
                    flush=True,
                )
        report["status"] = "passed"
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        report.update(lab.audit())
        (root / "service-permissions-verification.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(json.dumps({k: v for k, v in report.items() if k != "cases"}))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    verify(parser.parse_args().root.resolve())
